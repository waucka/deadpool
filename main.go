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
	"net/http"
	"os"
	"time"
	"sync"
	"strings"

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
	DefaultConfigPath = "/etc/deadpool.yaml"
	Version           = "0.1"
)

type awsConfig struct {
	Region  string `yaml:"region"`
	AccessKeyId     string                   `yaml:"access_key_id"`
	SecretAccessKey string                   `yaml:"secret_access_key"`
}

func (self *awsConfig) Validate() error {
	if len(self.Region) == 0 {
		return fmt.Errorf("Empty AWS region")
	}
	if len(self.AccessKeyId) == 0 {
		return fmt.Errorf("Empty AWS access key ID")
	}
	if len(self.SecretAccessKey) == 0 {
		return fmt.Errorf("Empty AWS secret access key")
	}
	return nil
}

type deadpoolConfig struct {
	// ListenAddr and ListenPort are for the built-in HTTP server for health checks
	ListenAddr string `yaml:"addr"`
	ListenPort int    `yaml:"port"`
	Aws awsConfig `yaml:"aws"`
	Mail *commonlib.MailConfig `yaml:"mail"`
	// SecretKey is used to prevent random jerks on the Internet from spamming the health-check endpoint
	SecretKey          string                   `yaml:"secret_key"`
	CheckIntervalSeconds int `yaml:"check_interval_seconds"`
	TimeoutSeconds int `yaml:"timeout_seconds"`
	LogLevel string `yaml:"log_level"`
	Checkers           map[string]yaml.MapSlice `yaml:"checkers"`
}

func (self *deadpoolConfig) Validate() error {
	if len(self.ListenAddr) == 0 {
		return fmt.Errorf("Empty HTTP listening address")
	}
	if self.ListenPort == 0 {
		self.ListenPort = 80
	}
	if self.ListenPort < 0 {
		return fmt.Errorf("Invalid HTTP listening port")
	}
	if len(self.SecretKey) == 0 {
		return fmt.Errorf("Empty HTTP secret key")
	}
	if self.CheckIntervalSeconds <= 0 {
		return fmt.Errorf("Empty or invalid check interval")
	}
	if self.TimeoutSeconds <= 0 {
		return fmt.Errorf("Empty or invalid health-check timeout")
	}
	if len(self.Checkers) == 0 {
		return fmt.Errorf("No checkers specified")
	}
	err := self.Aws.Validate()
	if err != nil {
		return err
	}
	if self.Mail != nil {
		err = self.Mail.Validate()
		if err != nil {
			return err
		}
	}
	return nil
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
		cli.BoolFlag{
			Name:  "dryrun",
			Usage: "Don't actually restart anything",
		},
	}
	app.Run(os.Args)
}

func loadCheckers(config deadpoolConfig, svc *ec2.EC2) map[string]commonlib.Checker {
	expectedCheckers := map[string]commonlib.CreateCheckerFunc{
		"openshift": openshift.Create,
	}
	checkers := make(map[string]commonlib.Checker)

	for name, create := range expectedCheckers {
		raw, ok := config.Checkers[name]
		if ok {
			log.Printf("Loading checker %s", name)
			checker, err := create(svc, raw)
			if err != nil {
				log.Fatalf("Failed to load checker %s: %s", name, err.Error())
			}
			checkers[name] = checker
			log.Printf("Loaded checker %s", name)
		}
	}

	return checkers
}

type daemonStatus struct {
	code       int
	msg        string
	lastUpdate time.Time
	mutex *sync.Mutex
}

func daemonProc(status *daemonStatus, checkers map[string]commonlib.Checker, config deadpoolConfig) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Daemon proc crashed!  %s", r)
		}
	}()
	log.Print("Daemon proc now running...")
	for {
		msgs := make([]string, 0)
		for name, checker := range checkers {
			log.Debugf("Running checker %s", name)
			checker.Execute(log.WithFields(log.Fields{
				"checker": name,
			}))
			log.Debugf("Getting status for checker %s", name)
			status, msg := checker.GetStatus()
			if !status {
				log.Debugf("Checker %s failed its health check: %s", name, msg)
				msgs = append(msgs, msg)
			}
		}
		// Random func to make defer work properly
		func() {
			status.mutex.Lock()
			defer status.mutex.Unlock()
			if len(msgs) > 0 {
				status.code = 500
				status.msg = strings.Join(msgs, "\n")
			} else {
				status.code = 200
				status.msg = "OK"
			}
		}()
		status.lastUpdate = time.Now()
		time.Sleep(time.Duration(config.CheckIntervalSeconds) * time.Second)
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

		if config.TimeoutSeconds - config.CheckIntervalSeconds < 10 {
			log.Fatal("timeout_seconds must be at least 10 more than check_interval_seconds")
		}

		err = config.Validate()
		if err != nil {
			log.Fatalf("Invalid configuration: %s", err.Error())
		}
	}
	commonlib.DRYRUN = c.Bool("dryrun")
	commonlib.Mail = config.Mail
	if config.LogLevel == "panic" {
		log.SetLevel(log.PanicLevel)
	} else if config.LogLevel == "fatal" {
		log.SetLevel(log.FatalLevel)
	} else if config.LogLevel == "error" {
		log.SetLevel(log.ErrorLevel)
	} else if config.LogLevel == "warning" {
		log.SetLevel(log.WarnLevel)
	} else if config.LogLevel == "info" {
		log.SetLevel(log.InfoLevel)
	} else if config.LogLevel == "debug" {
		log.SetLevel(log.DebugLevel)
	}
	log.Debug("Read config")

	sess := session.New(&aws.Config{
		Region:      aws.String(config.Aws.Region),
		Credentials: credentials.NewStaticCredentials(config.Aws.AccessKeyId, config.Aws.SecretAccessKey, ""),
	})
	svc := ec2.New(sess)

	checkers := loadCheckers(config, svc)

	status := daemonStatus{
		code:       400,
		msg:        "Not running yet",
		lastUpdate: time.Now(),
		mutex: &sync.Mutex{},
	}

	go daemonProc(&status, checkers, config)

	log.Printf("Starting HTTP server on %s:%d...", config.ListenAddr, config.ListenPort)
	r := gin.Default()
	r.GET("/health", func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader != config.SecretKey {
			c.String(http.StatusUnauthorized, "Bad or missing Authorization header")
			return
		}
		status.mutex.Lock()
		defer status.mutex.Unlock()
		if time.Now().Sub(status.lastUpdate) > time.Duration(config.TimeoutSeconds) * time.Second {
			c.String(http.StatusInternalServerError, "Checker goroutine not running")
			return
		}
		if status.code != 200 {
			c.String(status.code, status.msg)
			return
		}
		c.String(http.StatusOK, "OK")
	})

	r.Run(fmt.Sprintf("%s:%d", config.ListenAddr, config.ListenPort))
}
