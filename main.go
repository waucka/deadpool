package main

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
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/codegangsta/cli"
	"github.com/waucka/deadpool/commonlib"
	"gopkg.in/yaml.v2"

	// Checkers
	"github.com/waucka/deadpool/openshift"
)

var (
	ReqIdChars        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	ReqIdLen          = 16
	DefaultConfigPath = "/etc/deadpool.yaml"
	Version           = "0.1"
)

type deadpoolConfig struct {
	// ListenAddr and ListenPort are for the built-in HTTP server for health checks
	ListenAddr string `yaml:"addr"`
	ListenPort int    `yaml:"port"`
	EC2Region  string `yaml:"ec2_region"`
	// SecretKey is used to prevent random jerks on the Internet from spamming the health-check endpoint
	SecretKey          string                   `yaml:"secret_key"`
	AwsAccessKeyId     string                   `yaml:"aws_access_key_id"`
	AwsSecretAccessKey string                   `yaml:"aws_secret_access_key"`
	Checkers           map[string]yaml.MapSlice `yaml:"checkers"`
}

// gin middleware that assigns a random request ID to each request.
func reqIdMiddleware(c *gin.Context) {
	var reqIdBytes []byte
	for i := 0; i < ReqIdLen; i++ {
		reqIdBytes = append(reqIdBytes, ReqIdChars[rand.Intn(len(ReqIdChars))])
	}
	reqId := string(reqIdBytes)
	c.Set("reqId", reqId)
	c.Header("Secretshare-ReqId", reqId)
}

// Returns a logrus entry with fields based on the gin Context.
//
// This adds the `reqId` field containing the request ID populated by reqIdMiddleware().
func logger(c *gin.Context) *log.Entry {
	reqIdIface, exists := c.Get("reqId")
	if !exists {
		return log.WithFields(log.Fields{})
	}
	reqId, ok := reqIdIface.(string)
	if !ok {
		log.Error("reqId is not string")
		return log.WithFields(log.Fields{})
	}
	return log.WithFields(log.Fields{
		"reqId": reqId,
	})
}

func main() {
	app := cli.NewApp()
	app.Name = "deadpool"
	app.Usage = "Restart unresponsive EC2 instances"
	app.Version = Version
	app.Action = runServer
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "/etc/deadpool.yaml",
			Usage: "Configuration file",
		},
	}
	app.Run(os.Args)
}

type daemonStatus struct {
	code       int
	msg        string
	lastUpdate time.Time
}

func daemonProc(status *daemonStatus, config deadpoolConfig, svc *ec2.EC2) {
	expectedCheckers := map[string]commonlib.CreateCheckerFunc{
		"openshift": openshift.Create,
	}
	var checkers map[string]commonlib.Checker

	for name, create := range expectedCheckers {
		raw, ok := config.Checkers[name]
		if ok {
			log.Printf("Loading checker %s", name)
			checker, err := create(svc, raw)
			if err != nil {
				log.Fatalf("Failed to load checker %s: %s", name, err.Error())
			}
			checkers[name] = checker
		}
	}
	for {
		for name, checker := range checkers {
			checker.Execute(log.WithFields(log.Fields{
				"checker": name,
			}))
		}
		time.Sleep(30 * time.Second)
	}
}

func runServer(c *cli.Context) {
	var config deadpoolConfig
	{
		configPath := c.String("config")
		if len(configPath) == 0 {
			configPath = DefaultConfigPath
		}
		configFile, err := os.Open(configPath)
		if err != nil {
			log.Fatalf(`Failed to open config file "%s"`, configPath)
		}
		configData, err := ioutil.ReadAll(configFile)
		if err != nil {
			log.Fatalf(`Failed to read config file "%s"`, configPath)
		}
		err = yaml.Unmarshal(configData, &config)
		if err != nil {
			log.Fatalf(`Config file "%s" is not valid JSON`, configPath)
		}

		if len(config.ListenAddr) == 0 {
			config.ListenAddr = "0.0.0.0"
		}
	}

	sess := session.New(&aws.Config{
		Region:      aws.String(config.EC2Region),
		Credentials: credentials.NewStaticCredentials(config.AwsAccessKeyId, config.AwsSecretAccessKey, ""),
	})
	svc := ec2.New(sess)

	status := daemonStatus{
		code:       400,
		msg:        "Not running yet",
		lastUpdate: time.Now(),
	}

	go daemonProc(&status, config, svc)

	r := gin.Default()
	r.Use(reqIdMiddleware)
	r.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	r.Run(fmt.Sprintf("%s:%d", config.ListenAddr, config.ListenPort))
}
