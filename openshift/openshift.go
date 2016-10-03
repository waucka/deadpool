package openshift

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
	"encoding/json"
	"fmt"
	"time"
	"errors"
	"strings"
	"net/http"
	"io/ioutil"
	"crypto/x509"
	"crypto/tls"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/waucka/deadpool/commonlib"
	"gopkg.in/yaml.v2"
)

var (
	ErrUnexpectedReadyStatus = errors.New("Unexpected status field in \"Ready\" condition")
	ErrNoReadyCondition      = errors.New("Node did not report readiness")
	ErrEC2LookupFailed = errors.New("Failed to look up node info in EC2")
	ErrBadCaCert = errors.New("Failed to load CA certificate")
)

type NodeMatcher struct {
	EC2NamePrefix string `yaml:"name_prefix,omitempty"`
	Labels map[string]string `yaml:"labels,omitempty"`
}

type TestingConfig struct {
	ForceNotReady []string `yaml:"force_not_ready"`
}

type OpenShiftChecker struct {
	AccessToken string       `yaml:"token"`
	Host         string       `yaml:"host"`
	Port int `yaml:"port"`
	CaCertFile string `yaml:"ca_cert_file"`
	NodeMatchers []NodeMatcher `yaml:"node_matchers"`
	Testing TestingConfig `yaml:"testing"`
	client      *http.Client `yaml:"-"`
	svc         *ec2.EC2     `yaml:"-"`
	nodesUrl string `yaml:"-"`
	errors map[string]error `yaml:"-"`
	nodeErrors map[string]error `yaml:"-"`
	nodeAges map[string]time.Time `yaml:"-"`
}

func (self *OpenShiftChecker) Validate() error {
	if len(self.AccessToken) == 0 {
		return fmt.Errorf("Empty OpenShift access token")
	}
	if len(self.Host) == 0 {
		return fmt.Errorf("Empty OpenShift server host")
	}
	if self.Port == 0 {
		self.Port = 8443
	}
	if self.Port < 0 {
		return fmt.Errorf("Invalid OpenShift server port %s", self.Port)
	}
	return nil
}

// Since we don't need much of the data from the response, these
// structures don't represent the full JSON
type NodeMetadata struct {
	Name string `json:"name"`
	Labels map[string]string `json:"labels"`
}

type NodeCondition struct {
	Status             string `json:"status"`
	LastTransitionTime string `json:"lastTransitionTime"`
	Reason             string `json:"reason"`
	LastHeartbeatTime  string `json:"lastHeartbeatTime"`
	Message            string `json:"message"`
	Type               string `json:"type"`
}

type NodeStatus struct {
	Conditions []NodeCondition `json:"conditions"`
}

type NodeInfo struct {
	Metadata NodeMetadata `json:"metadata"`
	Status   NodeStatus   `json:"status"`
}

type NodeInfoResponse struct {
	Kind  string     `json:"kind"`
	Items []NodeInfo `json:"items"`
}

func (self *OpenShiftChecker) isNodeReady(node NodeInfo) (bool, error) {
	if len(self.Testing.ForceNotReady) > 0 {
		for _, name := range self.Testing.ForceNotReady {
			if node.Metadata.Name == name {
				return false, nil
			}
		}
	}
	// All this nonsense is inferred from the kubectl code
	// vendored into OpenShift Origin itself.  As far as I
	// can tell, there is no documented way to determine
	// node readiness.
	for _, condition := range node.Status.Conditions {
		if condition.Type == "Ready" {
			if condition.Status == "True" {
				return true, nil
			} else if condition.Status == "False" || condition.Status == "Unknown" {
				// We check for False or Unknown here because apparently it can
				// be either one!  Whee!
				return false, nil
			} else {
				return false, ErrUnexpectedReadyStatus
			}
		}
	}
	return false, ErrNoReadyCondition
}

func (self *OpenShiftChecker) GetStatus() (bool, string) {
	log.Debug("Checking for general errors")
	for location, err := range self.errors {
		if err != nil {
			return false, fmt.Sprintf("Failed during execution: [%s] %s", location, err.Error())
		}
	}

	log.Debug("Checking for per-node errors")
	for nodeName, err := range self.nodeErrors {
		if err != nil {
			return false, fmt.Sprintf("Failed to check or restart node: [%s] %s", nodeName, err.Error())
		}
	}

	log.Debug("Health check complete")
	return true, ""
}

func getTagValue(instance *ec2.Instance, tagName string) (string, bool) {
	for _, tag := range instance.Tags {
		if *tag.Key == tagName {
			return *tag.Value, true
		}
	}
	return "", false
}

func (self *OpenShiftChecker) matchNode(instance *ec2.Instance, node NodeInfo) (bool, error) {
	ec2Name, ok := getTagValue(instance, "Name")
	ec2OK := true
	if !ok {
		ec2OK = false
	}
	for _, matcher := range self.NodeMatchers {
		if matcher.Labels != nil {
			for labelName, labelValue := range matcher.Labels {
				nodeLabelValue, ok := node.Metadata.Labels[labelName]
				if ok && nodeLabelValue == labelValue {
					return true, nil
				}
			}
		}
		if matcher.EC2NamePrefix != "" {
			if !ec2OK {
				return false, ErrEC2LookupFailed
			}
			if strings.HasPrefix(ec2Name, matcher.EC2NamePrefix) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (self *OpenShiftChecker) Execute(logger *log.Entry) {
	logger.Debugf("Fetching %s", self.nodesUrl)
	req, err := http.NewRequest("GET", self.nodesUrl, nil)
	if err != nil {
		logger.Errorf("Failed to contact OpenShift: %s", err.Error())
		self.errors["contact-openshift"] = err
		return
	}
	self.errors["contact-openshift"] = nil
	req.Header.Add("Authorization", "Bearer "+self.AccessToken)
	req.Header.Add("Accept", "application/json")
	resp, err := self.client.Do(req)
	if err != nil {
		logger.Errorf("Failed to contact OpenShift: %s", err.Error())
		self.errors["contact-openshift"] = err
		return
	}
	self.errors["contact-openshift"] = nil
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("OpenShift returned HTTP status code %s", resp.StatusCode)
		logger.Errorf(err.Error())
		self.errors["contact-openshift"] = err
		return
	}
	self.errors["contact-openshift"] = nil
	logger.Debugf("GET %s %d", self.nodesUrl, resp.StatusCode)

	if resp.Body == nil {
		err = fmt.Errorf("Unexpected empty response from OpenShift")
		logger.Error(err.Error())
		self.errors["contact-openshift"] = err
		return
	}
	self.errors["contact-openshift"] = nil
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var nodeInfoResp NodeInfoResponse
	err = dec.Decode(&nodeInfoResp)
	if err != nil || nodeInfoResp.Kind != "NodeList" {
		logger.Errorf("Failed to decode response from OpenShift: %s", err.Error())
		self.errors["decode-response"] = err
		return
	}
	self.errors["decode-response"] = nil
	now := time.Now()
	// Purge old node error records
	logger.Debug("Purging old per-node error records...")
	for nodeName, lastSeen := range self.nodeAges {
		if now.Sub(lastSeen) > 5 * time.Minute {
			delete(self.nodeAges, nodeName)
			delete(self.nodeErrors, nodeName)
		}
	}
	// Process each node
	for _, node := range nodeInfoResp.Items {
		logger.Debugf("Processing OpenShift node %s", node.Metadata.Name)
		self.nodeErrors[node.Metadata.Name] = nil
		self.nodeAges[node.Metadata.Name] = now
		logger.Debugf("Looking up EC2 instance for node %s", node.Metadata.Name)
		instance, err := self.lookupInstance(node.Metadata.Name)
		if err != nil {
			logger.Errorf("Failed to find EC2 instance corresponding to OpenShift node %s: %s", node.Metadata.Name, err.Error())
			self.nodeErrors[node.Metadata.Name] = err
			continue
		}
		logger.Debugf("Node %s corresponds to EC2 instance %s", node.Metadata.Name, *instance.InstanceId)

		logger.Debugf("Checking if node %s matches criteria", node.Metadata.Name)
		matched, err := self.matchNode(instance, node)
		if err != nil {
			logger.Errorf("Failed to check for match on node %s: %s", node.Metadata.Name, err.Error())
			self.nodeErrors[node.Metadata.Name] = err
			continue
		}
		if !matched {
			logger.Debugf("Node %s does not match criteria, skipping", node.Metadata.Name)
			continue
		}

		logger.Debugf("Checking if node %s is ready", node.Metadata.Name)
		ok, err := self.isNodeReady(node)
		if err != nil {
			logger.Errorf("Failed to determine readiness of node %s: %s", node.Metadata.Name, err.Error())
			self.nodeErrors[node.Metadata.Name] = err
			continue
		}
		if !ok {
			openshiftName := node.Metadata.Name
			ec2Id := *instance.InstanceId
			ec2Name, err := commonlib.GetInstanceName(instance)
			if err != nil {
				ec2Name = ec2Id
			}
			logger.Infof("Node %s is not ready!", node.Metadata.Name)
			err = commonlib.RestartInstance(self.svc, ec2Id)
			if err != nil {
				logger.Errorf("Failed to restart node %s (instance %s): %s", openshiftName, ec2Id, err.Error())
				if err == commonlib.ErrInstanceTerminated {
					logger.Errorf("Node %s (instance %s) was terminated, so this is probably not a problem.", openshiftName, ec2Id, err.Error())
				} else {
					self.nodeErrors[node.Metadata.Name] = err
				}
				mailErr := commonlib.SendMail(fmt.Sprintf("Failed to restart OpenShift node %s (EC2 instance %s)", openshiftName, ec2Name), err.Error())
				if mailErr != nil {
					log.Errorf("Failed to send email: %s", mailErr.Error())
				}
			} else {
				logger.Infof("Node %s (instance %s) has been restarted.", openshiftName, ec2Id)
				mailErr := commonlib.SendMail(fmt.Sprintf("Restarted OpenShift node %s (EC2 instance %s)", openshiftName, ec2Name), "Does a DNS entry need to be updated?")
				if mailErr != nil {
					log.Errorf("Failed to send email: %s", mailErr.Error())
				}
			}
		} else {
			logger.Debugf("Node %s is ready", node.Metadata.Name)
		}
	}
}

func (self *OpenShiftChecker) lookupInstance(nodeName string) (*ec2.Instance, error) {
	descParams := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name: aws.String("private-dns-name"),
				Values: []*string{
					&nodeName,
				},
			},
		},
		DryRun: aws.Bool(false),
	}
	instance, err := commonlib.DescribeOneInstance(self.svc, descParams)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func Create(svc *ec2.EC2, raw yaml.MapSlice) (commonlib.Checker, error) {
	checker := &OpenShiftChecker{
		svc: svc,
		errors: make(map[string]error),
		nodeErrors: make(map[string]error),
		nodeAges: make(map[string]time.Time),
	}

	// DEAR GOD THIS IS HIDEOUS
	bytes, err := yaml.Marshal(raw)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(bytes, checker)
	if err != nil {
		return nil, err
	}

	checker.nodesUrl = fmt.Sprintf("https://%s:%d/api/v1/nodes", checker.Host, checker.Port)
	if len(checker.CaCertFile) > 0 {
		caCert, err := ioutil.ReadFile(checker.CaCertFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, ErrBadCaCert
		}
		tlsConfig := &tls.Config{
			RootCAs: caCertPool,
		}
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		checker.client = &http.Client{
			Transport: transport,
		}
	} else {
		checker.client = &http.Client{}
	}

	return checker, nil
}
