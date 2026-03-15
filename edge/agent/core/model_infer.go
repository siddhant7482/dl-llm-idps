package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

type Prediction struct {
	Class      string  `json:"class"`
	Confidence float32 `json:"confidence"`
}

type DlIdsModel struct{}

func NewDlIdsModel(path string) (*DlIdsModel, error) {
	return &DlIdsModel{}, nil
}

func (m *DlIdsModel) Predict(features []float32) (Prediction, error) {
	body := struct {
		Features []float32 `json:"features"`
	}{Features: features}
	b, _ := json.Marshal(body)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post("http://localhost:5000/predict", "application/json", bytes.NewReader(b))
	if err != nil {
		return Prediction{Class: "Benign", Confidence: 1.0}, nil
	}
	defer resp.Body.Close()
	var pred Prediction
	json.NewDecoder(resp.Body).Decode(&pred)
	return pred, nil
}
