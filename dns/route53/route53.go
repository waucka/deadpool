package route53

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
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/waucka/deadpool/commonlib"
	"gopkg.in/yaml.v2"
)

var (
	dnsRecordType = "A"
)

type Route53Updater struct {
	Domain   string           `yaml:"domain"`
	TTL      int64            `yaml:"ttl"`
	Simulate bool             `yaml:"simulate"`
	svc      *route53.Route53 `yaml:"-"`
	logger   *log.Entry       `yaml:"-"`
}

func (self *Route53Updater) SetDNS(instance *ec2.Instance) error {
	// Yes, we retrieve the hosted zone's ID every time we update DNS.
	// Hopefully, deadpool-triggered node restarts (and thus DNS updates)
	// are a rare event, so this won't be a big deal.  Plus, it would be
	// really annoying if you needed to remember to restart deadpool after
	// deleting and recreating a hosted zone.
	hostedZonesResponse, err := self.svc.ListHostedZonesByName(&route53.ListHostedZonesByNameInput{
		DNSName: &self.Domain,
		// Typing this line made me want to cry.
		MaxItems: aws.String("1"),
	})
	if err != nil {
		return err
	}

	if len(hostedZonesResponse.HostedZones) == 0 {
		return fmt.Errorf("No such hosted zone: %s", self.Domain)
	}

	zoneId := hostedZonesResponse.HostedZones[0].Id

	instanceName, err := commonlib.GetInstanceName(instance)
	if err != nil {
		return err
	}

	fqdn := fmt.Sprintf("%s.%s", instanceName, self.Domain)

	if self.Simulate {
		self.logger.Infof("Would set DNS: A %s %s", fqdn, *instance.PublicIpAddress)
		return nil
	}

	params := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action: aws.String("UPSERT"),
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: &fqdn,
						Type: &dnsRecordType,
						TTL:  &self.TTL,
						ResourceRecords: []*route53.ResourceRecord{
							{
								Value: instance.PublicIpAddress,
							},
						},
					},
				},
			},
		},
		HostedZoneId: zoneId,
	}
	_, err = self.svc.ChangeResourceRecordSets(params)
	if err != nil {
		self.logger.Infof("Set DNS: A %s %s", fqdn, *instance.PublicIpAddress)
	} else {
		self.logger.Errorf("Failed to set DNS: A %s %s (%s)", fqdn, *instance.PublicIpAddress, err.Error())
	}
	return err
}

func Create(sess *session.Session, raw yaml.MapSlice) (commonlib.DNSUpdater, error) {
	updater := &Route53Updater{
		svc: route53.New(sess),
		logger: log.WithFields(log.Fields{
			"dns": "route53",
		}),
	}

	// DEAR GOD THIS IS HIDEOUS
	bytes, err := yaml.Marshal(raw)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(bytes, updater)
	if err != nil {
		return nil, err
	}

	return updater, nil
}
