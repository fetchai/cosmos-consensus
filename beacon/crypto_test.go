package beacon

import (
	"testing"
)

func TestSign(t *testing.T) {
	InitialiseMcl()
	cabinet_size := uint64(4)

	// Information generic to all
	generator := "Fetch.ai Generator G"
	group_public_key := "1 13617830084396363337718434908852501458428164735125379368446532291036931854085 16638751093805422682570463783831011691772252489838589256909687996936790420765 5486323158821181154783464192503123612629027242960810671838168084617904106002 5100770784701939377150040548470418138755495771397245984025364438080419605892"
	public_keys_vec := NewStringVector()
	defer DeleteStringVector(public_keys_vec)
	public_keys_vec.Add("1 1516668801111681192333855390709478388776976469635871255458339826120799995629 15404529425458480529934186883697956050977293669493681499925623406164981834678 2909596554463291940088543404664325870552709259638431744055983125541910737735 4556738626556924071180879837237263170421437053719948675689585886350044310797")
	public_keys_vec.Add("1 3704221052526089554640337799625431284241069449509753178319378880511260249112 16482428412860019658119201434864888642499711523158928674681528157581891142950 14271463299280191075489899760516851597662863145378360357767416191043697538562 10529005999825913612823609968014403303527425830688219143472065428954174433457")
	public_keys_vec.Add("1 10142327438716345424918983727546710953417724086728488935993615208644637432975 7248449580689388853293388155366304708565381580101208142814199673335048709192 14145028462281911032212016228766356111041462230042498369155150989624363250056 11744666229255773236044276247636062184616462117256576236564676831107656008974")
	public_keys_vec.Add("1 12205346776628556235494143052804720250559505650750859848258906907464000413257 5670375033225567291360576105475019849345682456357000720430210287982881351648 2488718167161835728179659071341250190481360204196012184684671416154312205916 15456091653783616539293690843847074257212709062535377897818432047446292814401")
	private_keys_vec := NewStringVector()
	defer DeleteStringVector(private_keys_vec)
	private_keys_vec.Add("16534938823402113060673125801175683948490899769133048130634739353200748604473")
	private_keys_vec.Add("13127572624580735827410917700042683304450687818872394812692835249595633529202")
	private_keys_vec.Add("8977176623456312920391114204025776708798620755842542578785206958447612244442")
	private_keys_vec.Add("4083750820028844339613715313124964161534698580043491428911854479756684750193")

	// Create permanent entropy generator for computing group signature
	aeon_keys := NewDKGKeyInformation()
	defer DeleteDKGKeyInformation(aeon_keys)
	aeon_keys.SetPrivate_key(private_keys_vec.Get(0))
	aeon_keys.SetGroup_public_key(group_public_key)
	aeon_keys.SetPublic_key_shares(public_keys_vec)

	entropy_generator := NewEntropyGenerationInterface(aeon_keys, generator)
	defer DeleteEntropyGenerationInterface(entropy_generator)

	message := "HelloWorld"
	signature := entropy_generator.Sign(message)
	if !entropy_generator.Verify(message, signature, uint64(0)) {
		t.Error("entropy_generator.Verify == false")
	}
	// Collect signatures in map
	signature_shares := NewIntStringMap()
	defer DeleteIntStringMap(signature_shares)
	signature_shares.Set(0, signature)

	// Create aeon keys for each cabinet member and entropy generators
	for i := uint64(1); i < cabinet_size; i++ {
		aeon_keys_temp := NewDKGKeyInformation()
		defer DeleteDKGKeyInformation(aeon_keys_temp)
		aeon_keys_temp.SetPrivate_key(private_keys_vec.Get(int(i)))
		aeon_keys_temp.SetGroup_public_key(group_public_key)
		aeon_keys_temp.SetPublic_key_shares(public_keys_vec)

		entropy_generator_temp := NewEntropyGenerationInterface(aeon_keys_temp, generator)
		defer DeleteEntropyGenerationInterface(entropy_generator_temp)

		signature_temp := entropy_generator_temp.Sign(message)
		if !entropy_generator_temp.Verify(message, signature_temp, uint64(i)) {
			t.Error("entropy_generator.Verify == false")
		}
		signature_shares.Set(int(i), signature_temp)
	}
	group_signature := entropy_generator.ComputeGroupSignature(signature_shares)
	if !entropy_generator.VerifyGroupSignature(message, group_signature) {
		t.Error("entropy_generator.VerifyGroupSignature == false")
	}
}
