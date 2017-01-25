package anticaptcha

type TaskResult struct {
	Cost       float64 `json:"cost,string"`
	Ip         string  `json:"ip"`
	CreateTime int     `json:"createTime"`
	EndTime    int     `json:"endTime"`
	SolveCount int     `json:"solveCount,string"`
}

type taskResult struct {
	respErr
	Status string `json:"status"`
}
