package commonlib

import (
	"errors"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"gopkg.in/yaml.v2"
)

var (
	ErrNoSuchInstance      = errors.New("Instance does not exist")
	ErrTooManyReservations = errors.New("Instance has too many reservations")
	ErrTooManyInstances    = errors.New("Reservation has too many instances")
	ErrStartTimeout        = errors.New("Instance failed to start within 1 minute")
	ErrStopTimeout         = errors.New("Instance failed to stop within 5 minutes")
)

type Checker interface {
	Execute(*log.Entry)
	GetStatus() (bool, string)
}

type CreateCheckerFunc func(*ec2.EC2, yaml.MapSlice) (Checker, error)

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

func stopInstance(svc *ec2.EC2, id string) error {
	params := &ec2.StopInstancesInput{
		InstanceIds: []*string{
			&id,
		},
		DryRun: aws.Bool(false),
		Force:  aws.Bool(false),
	}
	_, err := svc.StopInstances(params)
	if err != nil {
		return err
	}

	descParams := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			&id,
		},
		DryRun: aws.Bool(false),
	}
	start := time.Now()
	for time.Now().Sub(start) < 5*time.Minute {
		instance, err := DescribeOneInstance(svc, descParams)
		if err != nil {
			return err
		}
		// 80 = Stopped
		if *instance.State.Code == 80 {
			return nil
		}
		time.Sleep(30 * time.Second)
	}

	return ErrStopTimeout
}

func startInstance(svc *ec2.EC2, id string) error {
	params := &ec2.StartInstancesInput{
		InstanceIds: []*string{
			&id,
		},
		DryRun: aws.Bool(false),
	}
	_, err := svc.StartInstances(params)
	if err != nil {
		return err
	}

	descParams := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			&id,
		},
		DryRun: aws.Bool(false),
	}
	start := time.Now()
	for time.Now().Sub(start) < 1*time.Minute {
		instance, err := DescribeOneInstance(svc, descParams)
		if err != nil {
			return err
		}
		// 16 = Running
		if *instance.State.Code == 16 {
			return nil
		}
		time.Sleep(30 * time.Second)
	}

	return ErrStartTimeout
}

func RestartInstance(svc *ec2.EC2, id string) error {
	err := stopInstance(svc, id)
	if err != nil {
		return err
	}
	err = startInstance(svc, id)
	if err != nil {
		return err
	}
	return nil
}
