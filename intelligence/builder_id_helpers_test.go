package intelligence

import "encoding/json"

func marshalReportForTest(r *Report) ([]byte, error) { return json.Marshal(r) }

func unmarshalReportForTest(b []byte) (*Report, error) {
	var out Report
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
