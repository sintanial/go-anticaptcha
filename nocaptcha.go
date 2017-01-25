package anticaptcha

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"time"
)

type NoCaptchaProxylessTask struct {
	WebsiteURL    string `json:"websiteURL"`
	WebsiteKey    string `json:"websiteKey, omitempty"`
	WebsiteSToken string `json:"websiteSToken"`
}

type NoCaptchaTask struct {
	NoCaptchaProxylessTask
	ProxyType     string `json:"proxyType"`
	ProxyAddress  string `json:"proxyAddress"`
	ProxyPort     int    `json:"proxyPort"`
	ProxyLogin    string `json:"proxyLogin, omitempty"`
	ProxyPassword string `json:"proxyPassword, omitempty"`
	UserAgent     string `json:"userAgent"`
	Cookies       string `json:"cookies, omitempty"`
}

type NoCaptchaResolver struct {
	Settings
}

func (self *NoCaptchaResolver) CreatedProxylessTask(t NoCaptchaProxylessTask) (int, error) {
	task := struct {
		NoCaptchaProxylessTask
		Type string `json:"type"`
	}{t, "NoCaptchaTaskProxyless"}

	reqbody, err := json.Marshal(reqData{Key: self.Key, Task: task, Language: self.getLang()})
	if err != nil {
		return 0, err
	}

	resp, err := self.getClient().Post("http://api.anti-captcha.com/createTask", "application/json", bytes.NewReader(reqbody))
	if err != nil {
		return 0, err
	}

	return parseTaskIdFromResp(resp)
}

func (self *NoCaptchaResolver) CreateTask(t NoCaptchaTask) (int, error) {
	task := struct {
		NoCaptchaTask
		Type string `json:"type"`
	}{t, "NoCaptchaTask"}

	reqbody, err := json.Marshal(reqData{Key: self.Key, Task: task, Language: self.getLang()})
	if err != nil {
		return 0, err
	}

	resp, err := self.getClient().Post("http://api.anti-captcha.com/createTask", "application/json", bytes.NewReader(reqbody))
	if err != nil {
		return 0, err
	}

	return parseTaskIdFromResp(resp)
}

type NoCaptchaSolution struct {
	GRecaptchaResponse string `json:"gRecaptchaResponse"`
}

type NoCaptchaResult struct {
	TaskResult
	Solution NoCaptchaSolution `json:"solution"`
}

func (self *NoCaptchaResolver) Solution(t NoCaptchaTask) (string, error) {
	res, err := self.Resolve(t)
	if err != nil {
		return "", err
	}

	return res.Solution.GRecaptchaResponse, nil
}

func (self *NoCaptchaResolver) SolutionProxyless(t NoCaptchaProxylessTask) (string, error) {
	res, err := self.ResolveProxyless(t)
	if err != nil {
		return "", err
	}

	return res.Solution.GRecaptchaResponse, nil
}

func (self *NoCaptchaResolver) ResolveProxyless(t NoCaptchaProxylessTask) (*NoCaptchaResult, error) {
	return self.resolve(t)
}

func (self *NoCaptchaResolver) Resolve(t NoCaptchaTask) (*NoCaptchaResult, error) {
	return self.resolve(t)
}

func (self *NoCaptchaResolver) resolve(t interface{}) (*NoCaptchaResult, error) {
	var taskId int
	var err error
	if task, ok := t.(NoCaptchaTask); ok {
		taskId, err = self.CreateTask(task)
		if err != nil {
			return nil, err
		}
	} else if task, ok := t.(NoCaptchaProxylessTask); ok {
		taskId, err = self.CreatedProxylessTask(task)
		if err != nil {
			return nil, err
		}
	}

	answerch := make(chan *NoCaptchaResult)
	errch := make(chan error)

	var timer *time.Timer
	attempts := 0
	timer = time.AfterFunc(self.getPingTime(), func() {
		attempts++

		answer, err := self.TaskResult(taskId)
		if err != nil {
			if err == ErrCaptchaInProcess {
				if self.MaxCheckAttempts > 0 && attempts > self.MaxCheckAttempts {
					errch <- ErrAttemptsExceed
					return
				} else if int64(self.MaxTimeAttempts) > 0 && attempts*int(self.getPingTime().Seconds()) > int(self.MaxTimeAttempts.Seconds()) {
					errch <- ErrCheckTimeout
					return
				}

				timer.Reset(self.getPingTime())
				return
			}

			errch <- err
			return
		}

		answerch <- answer
	})

	select {
	case err := <-errch:
		return nil, err
	case res := <-answerch:
		return res, nil
	}
}

func (self *NoCaptchaResolver) TaskResult(taskId int) (*NoCaptchaResult, error) {
	reqdata := struct {
		Key    string `json:"clientKey"`
		TaskId int    `json:"taskId"`
	}{self.Key, taskId}

	reqbody, err := json.Marshal(reqdata)
	if err != nil {
		return nil, err
	}

	resp, err := self.getClient().Post("https://api.anti-captcha.com/getTaskResult", "application/json", bytes.NewReader(reqbody))
	if err != nil {
		return nil, err
	}

	respbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var respdata struct {
		NoCaptchaResult
		taskResult
	}

	if err := json.Unmarshal(respbody, &respdata); err != nil {
		return nil, err
	}

	if respdata.ErrorId > 0 {
		return nil, respdata.ToErr()
	}

	if respdata.Status == statusProcessing {
		return nil, ErrCaptchaInProcess
	}

	return &respdata.NoCaptchaResult, nil
}

func (self NoCaptchaResolver) TaskSolution(taskId int) (string, error) {
	res, err := self.TaskResult(taskId)
	if err != nil {
		return "", err
	}

	return res.Solution.GRecaptchaResponse, nil
}
