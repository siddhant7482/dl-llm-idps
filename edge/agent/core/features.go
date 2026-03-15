package core

import "math"

func fMean(sum float64, count uint64) float32 {
	if count == 0 {
		return 0
	}
	return float32(sum / float64(count))
}

func fStd(sum float64, sq float64, count uint64) float32 {
	if count == 0 {
		return 0
	}
	m := sum / float64(count)
	v := (sq / float64(count)) - m*m
	if v < 0 {
		v = 0
	}
	return float32(math.Sqrt(v))
}

func BuildFeatures(key FlowKey, s FlowState) []float32 {
	out := make([]float32, 52)
	dur := float32(s.LastSeen.Sub(s.FirstSeen).Seconds())
	if dur < 0 {
		dur = 0
	}
	out[0] = dur
	out[1] = float32(s.TotalFwdPkts)
	out[2] = float32(s.TotalBwdPkts)
	out[3] = float32(s.FwdLenSum)
	out[4] = float32(s.BwdLenSum)
	out[5] = float32(s.FwdLenMax)
	out[6] = fMean(s.FwdLenSum, s.TotalFwdPkts)
	out[7] = fStd(s.FwdLenSum, s.FwdLenSqSum, s.TotalFwdPkts)
	out[8] = fMean(s.BwdLenSum, s.TotalBwdPkts)
	out[9] = fStd(s.BwdLenSum, s.BwdLenSqSum, s.TotalBwdPkts)
	totalBytes := s.FwdLenSum + s.BwdLenSum
	totalPkts := float32(s.TotalFwdPkts + s.TotalBwdPkts)
	if dur > 0 {
		out[10] = float32(totalBytes) / dur
		out[11] = totalPkts / dur
	} else {
		out[10] = 0
		out[11] = 0
	}
	// Flow IAT stats
	if s.FlowIatCount > 0 {
		out[12] = float32(s.FlowIatSum / float64(s.FlowIatCount))
		out[13] = fStd(s.FlowIatSum, s.FlowIatSqSum, s.FlowIatCount)
		out[14] = float32(s.FlowIatMax)
		out[15] = float32(s.FlowIatMin)
	}
	// Fwd IAT
	out[16] = float32(s.FwdIatSum)
	if s.FwdIatCount > 0 {
		out[17] = float32(s.FwdIatSum / float64(s.FwdIatCount))
		out[18] = fStd(s.FwdIatSum, s.FwdIatSqSum, s.FwdIatCount)
		out[19] = float32(s.FwdIatMax)
		out[20] = float32(s.FwdIatMin)
	}
	// Bwd IAT
	out[21] = float32(s.BwdIatSum)
	if s.BwdIatCount > 0 {
		out[22] = float32(s.BwdIatSum / float64(s.BwdIatCount))
		out[23] = fStd(s.BwdIatSum, s.BwdIatSqSum, s.BwdIatCount)
		out[24] = float32(s.BwdIatMax)
		out[25] = float32(s.BwdIatMin)
	}
	// Header lengths
	out[26] = float32(s.FwdHdrLenSum)
	out[27] = float32(s.BwdHdrLenSum)
	// Directional packets per second
	if dur > 0 {
		out[28] = float32(s.TotalFwdPkts) / dur
		out[29] = float32(s.TotalBwdPkts) / dur
	}
	out[30] = float32(s.AllLenMax)
	totalCount := uint64(s.TotalFwdPkts + s.TotalBwdPkts)
	out[31] = fMean(s.AllLenSum, totalCount)
	out[32] = fStd(s.AllLenSum, s.AllLenSqSum, totalCount)
	std := float64(out[32])
	out[33] = float32(std * std)
	if totalCount > 0 {
		out[34] = float32(s.AllLenSum / float64(totalCount))
	} else {
		out[34] = 0
	}
	out[35] = fMean(s.FwdLenSum, s.TotalFwdPkts)
	out[36] = fMean(s.BwdLenSum, s.TotalBwdPkts)
	out[37] = float32(s.TotalFwdPkts)
	out[38] = float32(s.FwdLenSum)
	out[39] = float32(s.TotalBwdPkts)
	out[40] = float32(s.BwdLenSum)
	// Init windows and active data packets are not tracked yet
	out[41] = 0
	out[42] = 0
	out[43] = 0
	// Active/Idle stats
	if s.ActiveCount > 0 {
		out[44] = float32(s.ActiveSum / float64(s.ActiveCount))
		out[45] = fStd(s.ActiveSum, s.ActiveSqSum, s.ActiveCount)
		out[46] = float32(s.ActiveMax)
		out[47] = float32(s.ActiveMin)
	}
	if s.IdleCount > 0 {
		out[48] = float32(s.IdleSum / float64(s.IdleCount))
		out[49] = fStd(s.IdleSum, s.IdleSqSum, s.IdleCount)
		out[50] = float32(s.IdleMax)
		out[51] = float32(s.IdleMin)
	}
	return out
}
