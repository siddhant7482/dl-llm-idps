package core

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	ort "github.com/yalue/onnxruntime_go"
)

type Prediction struct {
	Class      string  `json:"class"`
	Confidence float32 `json:"confidence"`
}

type DlIdsModel struct {
	useRemote   bool
	remoteURL   string
	onnxReady   bool
	dynSess     *ort.DynamicSession[ort.FloatData, ort.FloatData]
	inNames     []string
	outNames    []string
	outShape    []int64
	classLabels []string
}

func softmax(x []float32) []float32 {
	m := float32(-1e9)
	for _, v := range x {
		if v > m {
			m = v
		}
	}
	var sum float64
	out := make([]float32, len(x))
	for i := range x {
		e := float32(math.Exp(float64(x[i] - m)))
		out[i] = e
		sum += float64(e)
	}
	for i := range out {
		out[i] = float32(float64(out[i]) / sum)
	}
	return out
}

func NewDlIdsModel(path string) (*DlIdsModel, error) {
	url := os.Getenv("IDS_URL")
	if url == "" {
		url = "http://localhost:5000/predict"
	}
	lbl := os.Getenv("CLASS_LABELS")
	var labels []string
	if lbl != "" {
		labels = strings.Split(lbl, ",")
	} else {
		labels = []string{"Benign", "DDOS attack-HOIC"}
	}
	m := &DlIdsModel{useRemote: true, remoteURL: url, classLabels: labels}
	if path != "" && strings.HasSuffix(strings.ToLower(path), ".onnx") {
		lib := os.Getenv("ONNXRUNTIME_SHARED_LIBRARY_PATH")
		if lib != "" {
			ort.SetSharedLibraryPath(lib)
		}
		if err := ort.InitializeEnvironment(); err == nil {
			inInfo, outInfo, err := ort.GetInputOutputInfo(path)
			if err == nil && len(inInfo) > 0 && len(outInfo) > 0 {
				inNames := make([]string, len(inInfo))
				for i := range inInfo {
					inNames[i] = inInfo[i].Name
				}
				outNames := make([]string, len(outInfo))
				for i := range outInfo {
					outNames[i] = outInfo[i].Name
				}
				ds, err := ort.NewDynamicSession[ort.FloatData, ort.FloatData](path, inNames, outNames)
				if err == nil {
					m.useRemote = false
					m.onnxReady = true
					m.dynSess = ds
					m.inNames = inNames
					m.outNames = outNames
					if len(outInfo[0].Shape) > 0 {
						m.outShape = make([]int64, len(outInfo[0].Shape))
						copy(m.outShape, outInfo[0].Shape)
					} else {
						m.outShape = []int64{1, int64(len(labels))}
					}
				}
			}
		}
	}
	return m, nil
}

func (m *DlIdsModel) Predict(features []float32) (Prediction, error) {
	if !m.onnxReady || m.useRemote {
		body := struct {
			Features []float32 `json:"features"`
		}{Features: features}
		b, _ := json.Marshal(body)
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Post(m.remoteURL, "application/json", bytes.NewReader(b))
		if err != nil {
			return Prediction{Class: "Benign", Confidence: 1.0}, nil
		}
		defer resp.Body.Close()
		var pred Prediction
		json.NewDecoder(resp.Body).Decode(&pred)
		return pred, nil
	}
	inShape := ort.NewShape(1, int64(len(features)))
	inData := make([]ort.FloatData, len(features))
	for i := range features {
		inData[i] = ort.FloatData(features[i])
	}
	inTensor, _ := ort.NewTensor[ort.FloatData](inShape, inData)
	outTensor, _ := ort.NewEmptyTensor[ort.FloatData](ort.NewShape(m.outShape...))
	err := m.dynSess.Run([]*ort.Tensor[ort.FloatData]{inTensor}, []*ort.Tensor[ort.FloatData]{outTensor})
	if err != nil {
		return Prediction{Class: "Benign", Confidence: 1.0}, nil
	}
	outData := outTensor.GetData()
	p := make([]float32, len(outData))
	for i := range outData {
		p[i] = float32(outData[i])
	}
	probs := softmax(p)
	best := 0
	for i := 1; i < len(probs); i++ {
		if probs[i] > probs[best] {
			best = i
		}
	}
	cl := "Benign"
	if best < len(m.classLabels) {
		cl = m.classLabels[best]
	}
	return Prediction{Class: cl, Confidence: probs[best]}, nil
}
