package openshift

import (
	"encoding/json"
	"errors"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/waucka/deadpool/commonlib"
	"gopkg.in/yaml.v2"
)

var (
	ErrUnexpectedReadyStatus = errors.New("Unexpected status field in \"Ready\" condition")
	ErrNoReadyCondition      = errors.New("Node did not report readiness")
)

type OpenShiftChecker struct {
	AccessToken string       `yaml:"token"`
	URL         string       `yaml:"master_url"`
	Client      *http.Client `yaml:"-"`
	svc         *ec2.EC2     `yaml:"-"`
}

// Since we don't need much of the data from the response, these
// structures don't represent the full JSON
type NodeMetadata struct {
	Name string `json:"name"`
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

func isNodeReady(node NodeInfo) (bool, error) {
	// All this nonsense is inferred from the kubectl code
	// vendored into OpenShift Origin itself.  As far as I
	// can tell, there is no documented way to determine
	// node readiness.
	for _, condition := range node.Status.Conditions {
		if condition.Type == "Ready" {
			if condition.Status == "True" {
				return true, nil
			} else if condition.Status == "False" {
				return false, nil
			} else {
				return false, ErrUnexpectedReadyStatus
			}
		}
	}
	return false, ErrNoReadyCondition
}

func (self *OpenShiftChecker) Execute(logger *log.Entry) {
	req, err := http.NewRequest("GET", self.URL, nil)
	if err != nil {
		logger.Printf("Failed to contact OpenShift: %s", err.Error())
		return
	}
	req.Header.Add("Authorization", "Bearer "+self.AccessToken)
	req.Header.Add("Accept", "application/json")
	resp, err := self.Client.Do(req)
	if err != nil {
		logger.Printf("Failed to contact OpenShift: %s", err.Error())
		return
	}

	if resp.Body == nil {
		logger.Print("Unexpected empty response from OpenShift")
		return
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var nodeInfoResp NodeInfoResponse
	err = dec.Decode(&nodeInfoResp)
	if err != nil || nodeInfoResp.Kind != "NodeList" {
		logger.Print("Failed to decode response from OpenShift")
		return
	}
	for _, node := range nodeInfoResp.Items {
		ok, err := isNodeReady(node)
		if err != nil {
			logger.Printf("Failed to determine readiness of node %s", node.Metadata.Name)
			continue
		}
		if !ok {
			logger.Printf("Node %s is not ready!", node.Metadata.Name)
			instanceId, err := self.lookupInstanceId(node.Metadata.Name)
			if err != nil {
				logger.Printf("Failed to find instance corresponding to node %s", node.Metadata.Name)
			}
			err = commonlib.RestartInstance(self.svc, instanceId)
			if err != nil {
				logger.Printf("Failed to restart node %s (instance %s)", node.Metadata.Name, instanceId)
			}
		}
	}
}

func (self *OpenShiftChecker) lookupInstanceId(nodeName string) (string, error) {
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
		return "", err
	}
	return *instance.InstanceId, nil
}

func (self *OpenShiftChecker) GetStatus() (bool, string) {
	return false, "NOT IMPLEMENTED"
}

func Create(svc *ec2.EC2, raw yaml.MapSlice) (commonlib.Checker, error) {
	checker := &OpenShiftChecker{
		svc: svc,
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
	return checker, nil
}
