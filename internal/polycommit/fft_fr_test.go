/*
forked from https://github.com/protolambda/go-kzg at Feb 2,2023
*/
package polycommit

import (
	"testing"

	"github.com/DyCAPSTeam/DyCAPS/internal/bls"
)

func TestFFTRoundtrip(t *testing.T) {
	fs := NewFFTSettings(4)
	data := make([]bls.Fr, fs.MaxWidth, fs.MaxWidth)
	for i := uint64(0); i < fs.MaxWidth; i++ {
		bls.AsFr(&data[i], i)
	}
	coeffs, err := fs.FFT(data, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := fs.FFT(coeffs, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range res {
		if got, expected := &res[i], &data[i]; !bls.EqualFr(got, expected) {
			t.Errorf("difference: %d: got: %s  expected: %s", i, bls.FrStr(got), bls.FrStr(expected))
		}
	}
	t.Log("zero", bls.FrStr(&bls.ZERO))
	t.Log("zero", bls.FrStr(&bls.ONE))
}

func TestInvFFT(t *testing.T) {
	fs := NewFFTSettings(4)
	data := make([]bls.Fr, fs.MaxWidth, fs.MaxWidth)
	for i := uint64(0); i < fs.MaxWidth; i++ {
		bls.AsFr(&data[i], i)
	}
	DebugFrs("input data", data)
	res, err := fs.FFT(data, true)
	if err != nil {
		t.Fatal(err)
	}
	DebugFrs("result", res)
	ToFr := func(v string) (out bls.Fr) {
		bls.SetFr(&out, v)
		return
	}
	expected := []bls.Fr{
		ToFr("26217937587563095239723870254092982918845276250263818911301829349969290592264"),
		ToFr("8864682297557565932517422087434646388650579555464978742404310425307854971414"),
		ToFr("42397926345479656069499145686287671633657326275595206970800938736622240188372"),
		ToFr("20829590431265536861492157516271359172322844207237904580180981500923098586768"),
		ToFr("26217937587563095241456442667129809078233411015607690300436955584351971573760"),
		ToFr("40905488090558605688319636812215252217941835718478251840326926365086504505065"),
		ToFr("42397926345479656066034000860214019314881056744907464192530686267856878225364"),
		ToFr("28940579956850634752414611731231234796717032005329840446009750351940536963695"),
		ToFr("26217937587563095239723870254092982918845276250263818911301829349969290592256"),
		ToFr("23495295218275555727033128776954731040973520495197797376593908347998044220817"),
		ToFr("10037948829646534413413739647971946522809495755620173630072972432081702959148"),
		ToFr("11530387084567584791128103695970713619748716782049385982276732334852076679447"),
		ToFr("26217937587563095237991297841056156759457141484919947522166703115586609610752"),
		ToFr("31606284743860653617955582991914606665367708293289733242422677199015482597744"),
		ToFr("10037948829646534409948594821898294204033226224932430851802719963316340996140"),
		ToFr("43571192877568624546930318420751319449039972945062659080199348274630726213098"),
	}
	for i := range res {
		if got := &res[i]; !bls.EqualFr(got, &expected[i]) {
			t.Errorf("difference: %d: got: %s  expected: %s", i, bls.FrStr(got), bls.FrStr(&expected[i]))
		}
	}
}

func TestEvaluatePolyInEvaluationForm(t *testing.T) {
	fs := NewFFTSettings(4)
	// coeffs
	data := make([]bls.Fr, fs.MaxWidth, fs.MaxWidth)
	for i := uint64(0); i < fs.MaxWidth; i++ {
		data[i] = *bls.RandomFr()
	}
	// coefficients to eval form
	res, err := fs.FFT(data, false)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		x := bls.RandomFr()
		var y1 bls.Fr
		bls.EvalPolyAt(&y1, data, x)

		var y2 bls.Fr
		bls.EvaluatePolyInEvaluationForm(&y2, res, x, fs.ExpandedRootsOfUnity[:fs.MaxWidth], 0)

		if !bls.EqualFr(&y1, &y2) {
			DebugFrs("y", []bls.Fr{y1, y2})
			t.Fatal("expected to evaluate to the same value")
		}
	}
}
