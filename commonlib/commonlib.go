package commonlib

// deadpool - restart unresponsive EC2 instances
// Copyright (C) 2016  Alexander Wauck
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/smtp"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"gopkg.in/yaml.v2"
)

var (
	ErrNoSuchInstance      = errors.New("Instance does not exist")
	ErrTooManyReservations = errors.New("Instance has too many reservations")
	ErrTooManyInstances    = errors.New("Reservation has too many instances")
	ErrStartTimeout        = errors.New("Instance failed to start within 1 minute")
	ErrStopTimeout         = errors.New("Instance failed to stop within 5 minutes")
	ErrInstanceTerminated  = errors.New("Instance was terminated")
	ErrInstanceNotRunning  = errors.New("Instance is not running")

	ErrNamelessInstance = errors.New("Instance has no name")

	instancePending      int64 = 0
	instanceRunning      int64 = 16
	instanceShuttingDown int64 = 32
	instanceTerminated   int64 = 48
	instanceStopping     int64 = 64
	instanceStopped      int64 = 80

	Mail *MailConfig = nil
	DNSUpdaterInstance DNSUpdater = nil

	DRYRUN = false
)

type MailPlainAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (self *MailPlainAuth) Validate() error {
	if len(self.Username) == 0 {
		return fmt.Errorf("Empty mail server username")
	}
	if len(self.Password) == 0 {
		return fmt.Errorf("Empty mail server password")
	}
	return nil
}

type MailConfig struct {
	Host      string         `yaml:"host"`
	Port      int            `yaml:"port"`
	StartTLS  bool           `yaml:"starttls"`
	Sender    string         `yaml:"sender"`
	Recipient string         `yaml:"recipient"`
	Auth      *MailPlainAuth `yaml:"auth"`
}

func (self *MailConfig) Validate() error {
	if len(self.Host) == 0 {
		return fmt.Errorf("Empty mail server host")
	}
	if self.Port == 0 {
		self.Port = 25
	}
	if self.Port < 0 {
		return fmt.Errorf("Invalid mail server port")
	}
	if len(self.Sender) == 0 {
		return fmt.Errorf("Empty sender")
	}
	if len(self.Recipient) == 0 {
		return fmt.Errorf("Empty recipient")
	}
	if self.Auth != nil {
		return self.Auth.Validate()
	}
	return nil
}

type Checker interface {
	Execute(*log.Entry)
	GetStatus() (bool, string)
}

type CreateCheckerFunc func(*ec2.EC2, yaml.MapSlice) (Checker, error)

type DNSUpdater interface {
	SetDNS(*ec2.Instance) error
}

type CreateDNSUpdaterFunc func(*session.Session, yaml.MapSlice) (DNSUpdater, error)

func DescribeOneInstance(svc *ec2.EC2, params *ec2.DescribeInstancesInput) (*ec2.Instance, error) {
	resp, err := svc.DescribeInstances(params)
	if err != nil {
		return nil, err
	}
	if len(resp.Reservations) > 1 {
		return nil, ErrTooManyReservations
	}
	if len(resp.Reservations) == 0 {
		return nil, ErrNoSuchInstance
	}
	resv := resp.Reservations[0]
	if len(resv.Instances) > 1 {
		return nil, ErrTooManyInstances
	}
	if len(resv.Instances) == 0 {
		return nil, ErrNoSuchInstance
	}
	return resv.Instances[0], nil
}

func GetInstanceName(instance *ec2.Instance) (string, error) {
	for _, tag := range instance.Tags {
		if *tag.Key == "Name" {
			return *tag.Value, nil
		}
	}
	return "", ErrNamelessInstance
}

func stopInstance(svc *ec2.EC2, id string) error {
	if DRYRUN {
		return nil
	}
	params := &ec2.StopInstancesInput{
		InstanceIds: []*string{
			&id,
		},
		DryRun: aws.Bool(false),
		Force:  aws.Bool(false),
	}
	descParams := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			&id,
		},
		DryRun: aws.Bool(false),
	}

	// Check to see if the instance is already stopped
	instance, err := DescribeOneInstance(svc, descParams)
	if err != nil {
		return err
	}
	if *instance.State.Code == instanceStopped || *instance.State.Code == instanceTerminated {
		return nil
	}

	// Stop the instance if it is not already stopping or shutting down
	if *instance.State.Code != instanceStopping && *instance.State.Code != instanceShuttingDown {
		_, err := svc.StopInstances(params)
		if err != nil {
			return err
		}
	}

	start := time.Now()
	for time.Now().Sub(start) < 5*time.Minute {
		instance, err := DescribeOneInstance(svc, descParams)
		if err != nil {
			return err
		}
		if *instance.State.Code == instanceStopped {
			return nil
		}
		if *instance.State.Code == instanceTerminated {
			return ErrInstanceTerminated
		}
		time.Sleep(30 * time.Second)
	}

	return ErrStopTimeout
}

func startInstance(svc *ec2.EC2, id string) error {
	if DRYRUN {
		return nil
	}
	params := &ec2.StartInstancesInput{
		InstanceIds: []*string{
			&id,
		},
		DryRun: aws.Bool(false),
	}
	descParams := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			&id,
		},
		DryRun: aws.Bool(false),
	}

	// Check to see if the instance is already running
	instance, err := DescribeOneInstance(svc, descParams)
	if err != nil {
		return err
	}
	if *instance.State.Code == instanceRunning {
		return nil
	}

	// Start the instance if it is not already starting
	if *instance.State.Code != instancePending {
		_, err := svc.StartInstances(params)
		if err != nil {
			return err
		}
	}

	start := time.Now()
	for time.Now().Sub(start) < 1*time.Minute {
		instance, err := DescribeOneInstance(svc, descParams)
		if err != nil {
			return err
		}
		if *instance.State.Code == instanceRunning {
			return nil
		}
		time.Sleep(30 * time.Second)
	}

	return ErrStartTimeout
}

func SendMail(subject, body string) error {
	if Mail == nil {
		// Do nothing if mail is not configured.
		// We don't want to force the user to configure mail.
		return nil
	}
	var writer io.WriteCloser
	var c *smtp.Client
	var err error
	if DRYRUN {
		c = nil
		writer = os.Stdout
		fmt.Fprintf(writer, "Would send email:\n")
		fmt.Fprintf(writer, "================================================================================\n")
		defer fmt.Fprintf(writer, "================================================================================\n")

	} else {
		c, err = smtp.Dial(fmt.Sprintf("%s:%d", Mail.Host, Mail.Port))
		if err != nil {
			return err
		}
		defer c.Quit()

		if Mail.StartTLS {
			err = c.StartTLS(&tls.Config{
				ServerName: Mail.Host,
			})
			if err != nil {
				return err
			}
		}

		if Mail.Auth != nil {
			err = c.Auth(smtp.PlainAuth("", Mail.Auth.Username, Mail.Auth.Password, Mail.Host))
			if err != nil {
				return err
			}
		}

		err = c.Mail(Mail.Sender)
		if err != nil {
			return err
		}
		err = c.Rcpt(Mail.Recipient)
		if err != nil {
			return err
		}

		writer, err = c.Data()
		if err != nil {
			return err
		}
		defer writer.Close()
	}

	_, err = fmt.Fprintf(writer, "From: %s\r\n", Mail.Sender)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "To: %s\r\n", Mail.Recipient)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "Date: %s\r\n", time.Now().Format("2 Jan 2006 15:04:05 -0700"))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "Subject: %s\r\n\r\n", subject)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, body)
	if err != nil {
		return err
	}

	// No need for \r\n.\r\n -- net/smtp takes care of that.

	return nil
}

func RestartInstance(svc *ec2.EC2, id string) error {
	if DRYRUN {
		log.Debugf("Would restart EC2 instance %s", id)
		return nil
	}
	log.Printf("Stopping EC2 instance %s", id)
	err := stopInstance(svc, id)
	if err != nil {
		return err
	}
	// Sleep for 5 seconds just in case
	time.Sleep(5 * time.Second)
	log.Printf("Starting EC2 instance %s", id)
	err = startInstance(svc, id)
	if err != nil {
		return err
	}
	log.Printf("EC2 instance %s started", id)
	// Sleep for 30 seconds to let the instance start services
	time.Sleep(30 * time.Second)
	return nil
}

func SetDNS(svc *ec2.EC2, id string) error {
	if DNSUpdaterInstance != nil {
		descParams := &ec2.DescribeInstancesInput{
			InstanceIds: []*string{
				&id,
			},
			DryRun: aws.Bool(false),
		}

		// Check to see if the instance is already stopped
		instance, err := DescribeOneInstance(svc, descParams)
		if err != nil {
			return err
		}
		if *instance.State.Code == instanceStopped || *instance.State.Code == instanceTerminated {
			return ErrInstanceNotRunning
		}
		return DNSUpdaterInstance.SetDNS(instance)
	}
	return nil
}
