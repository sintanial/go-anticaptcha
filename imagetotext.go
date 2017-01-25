package anticaptcha

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"time"
	"fmt"
)

const NumericNoNumbers = 1
const NumericOnlyNumbers = 2

type ImageToTextTask struct {
	Phrase     bool `json:"phrase, omitempty"`
	Case       bool `json:"case, omitempty"`
	Numeric    int  `json:"numeric, omitempty"`
	Math       bool `json:"math, omitempty"`
	MinRespLen int  `json:"minLength, omitempty"`
	MaxRespLen int  `json:"maxLength, omitempty"`
}
type imageToTextTask struct {
	ImageToTextTask

	Type string `json:"type"`
	Body string `json:"body"`
}

type ImageToTextResolver struct {
	Settings
}

func (self *ImageToTextResolver) Solution(captcha []byte, opts *ImageToTextTask) (string, error) {
	res, err := self.Resolve(captcha, opts)
	if err != nil {
		return "", err
	}

	return res.Solution.Text, nil
}

func (self *ImageToTextResolver) Resolve(captcha []byte, opts *ImageToTextTask) (*ImageToTextResult, error) {
	taskId, err := self.CreateTask(captcha, opts)
	if err != nil {
		return nil, err
	}

	fmt.Println("taskId", taskId)

	answerch := make(chan *ImageToTextResult)
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
				} else if int64(self.MaxTimeAttempts) > 0 && attempts * int(self.getPingTime().Seconds()) > int(self.MaxTimeAttempts.Seconds()) {
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

func (self *ImageToTextResolver) CreateTask(captcha []byte, opts *ImageToTextTask) (int, error) {
	task := struct {
		ImageToTextTask `json:"-"`

		Type string `json:"type"`
		Body string `json:"body"`
	}{
		Type: "ImageToTextTask",
		Body: base64.StdEncoding.EncodeToString(captcha),
	}

	if opts != nil {
		task.ImageToTextTask = *opts
	}

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

type ImageToTextSolution struct {
	Text string `json:"text"`
	Url  string `json:"url"`
}

type ImageToTextResult struct {
	TaskResult
	Solution ImageToTextSolution `json:"solution"`
}

func (self *ImageToTextResolver) TaskResult(taskId int) (*ImageToTextResult, error) {
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

	fmt.Println("response:", string(respbody))

	var respdata struct {
		ImageToTextResult
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

	return &respdata.ImageToTextResult, nil
}

func (self ImageToTextResolver) TaskSolution(taskId int) (string, error) {
	res, err := self.TaskResult(taskId)
	if err != nil {
		return "", err
	}

	return res.Solution.Text, nil
}
