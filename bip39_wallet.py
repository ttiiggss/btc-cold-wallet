#!/usr/bin/env python3
# Bitcoin-only cold wallet: user entropy -> 24 BIP-39 words -> master key -> 512 receive addresses (BIP-44).
# NO libraries: SHA-256/512, HMAC, PBKDF2, RIPEMD-160, secp256k1, Base58Check all implemented below.
# Only stdlib import is `os` (os.urandom). Runs on an OFFLINE machine: python3 bip39_wallet.py > wallet.txt
import os
P=2**256-2**32-977;N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
W="""abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo""".split()
A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# ---- SHA-256 ----
K256=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
R=lambda x,n:((x>>n)|(x<<(32-n)))&0xFFFFFFFF
def sha256(m):
 h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];m=bytearray(m);m+=b'\x80'+b'\x00'*((55-len(m))%64)+(len(m)*8).to_bytes(8,'big')
 for o in range(0,len(m),64):
  w=[int.from_bytes(m[o+i*4:o+i*4+4],'big') for i in range(16)]
  for i in range(16,64):w.append((w[i-16]+(R(w[i-15],7)^R(w[i-15],18)^w[i-15]>>3)+w[i-7]+(R(w[i-2],17)^R(w[i-2],19)^w[i-2]>>10))&0xFFFFFFFF)
  a,b,c,d,e,f,g,hh=h[:]
  for i in range(64):
   t=(hh+(R(e,6)^R(e,11)^R(e,25))+(e&f^~e&g)+K256[i]+w[i])&0xFFFFFFFF;s=R(a,2)^R(a,13)^R(a,22)
   a,b,c,d,e,f,g,hh=(t+(s+(a&b^a&c^b&c))&0xFFFFFFFF)&0xFFFFFFFF,a,b,c,(d+t)&0xFFFFFFFF,e,f,g
  h=[(x+y)&0xFFFFFFFF for x,y in zip(h,[a,b,c,d,e,f,g,hh])]
 return b''.join(x.to_bytes(4,'big') for x in h)
# ---- SHA-512 ----
K512=[0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817]
M64=0xFFFFFFFFFFFFFFFF
def sha512(m):
 h=[0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179];m=bytearray(m);m+=b'\x80'+b'\x00'*((111-len(m))%128)+(len(m)*8).to_bytes(16,'big')
 for o in range(0,len(m),128):
  w=[int.from_bytes(m[o+i*8:o+i*8+8],'big') for i in range(16)]
  for i in range(16,80):
   s0=((w[i-15]>>1)|(w[i-15]<<63))&M64^((w[i-15]>>8)|(w[i-15]<<56))&M64^(w[i-15]>>7);s1=((w[i-2]>>19)|(w[i-2]<<45))&M64^((w[i-2]>>61)|(w[i-2]<<3))&M64^(w[i-2]>>6)
   w.append((w[i-16]+s0+w[i-7]+s1)&M64)
  a,b,c,d,e,f,g,hh=h[:]
  for i in range(80):
   S1=((e>>14)|(e<<50))&M64^((e>>18)|(e<<46))&M64^((e>>41)|(e<<23))&M64;ch=e&f^(~e&M64)&g
   t=(hh+S1+ch+K512[i]+w[i])&M64;S0=((a>>28)|(a<<36))&M64^((a>>34)|(a<<30))&M64^((a>>39)|(a<<25))&M64;mj=a&b^a&c^b&c
   a,b,c,d,e,f,g,hh=(t+(S0+mj&M64))&M64,a,b,c,(d+t)&M64,e,f,g
  h=[(x+y)&M64 for x,y in zip(h,[a,b,c,d,e,f,g,hh])]
 return b''.join(x.to_bytes(8,'big') for x in h)
def hmac512(k,m):
 if len(k)>128:k=sha512(k)
 k+=b'\x00'*(128-len(k))
 return sha512(bytes(x^0x5c for x in k)+sha512(bytes(x^0x36 for x in k)+m))
def pbkdf2_hmac512(pw,salt,n=2048):
 u=hmac512(pw,salt+b'\x00\x00\x00\x01');x=int.from_bytes(u,'big')
 for _ in range(n-1):u=hmac512(pw,u);x^=int.from_bytes(u,'big')
 return x.to_bytes(64,'big')
# ---- RIPEMD-160 ----
RL=list(range(16))+[7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8]+[3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12]+[1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2]+[4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
RR=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12]+[6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2]+[15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13]+[8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14]+[12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
SL=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8]+[7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12]+[11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5]+[11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12]+[9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
SR=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6]+[9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11]+[9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5]+[15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8]+[8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
KL=[0,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E];KR=[0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0]
L=lambda x,n:((x<<n)|(x>>(32-n)))&0xFFFFFFFF
def f(j,x,y,z):return x^y^z if j<16 else(x&y|~x&z if j<32 else(x|~y)^z if j<48 else(x&z|y&~z if j<64 else x^(y|~z)))
def ripemd160(m):
 h=[0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0];m=bytearray(m);m+=b'\x80'+b'\x00'*((55-len(m))%64)+(len(m)*8).to_bytes(8,'little')
 for o in range(0,len(m),64):
  x=[int.from_bytes(m[o+i*4:o+i*4+4],'little') for i in range(16)];a,b,c,d,e=h;A,B,C,D,E=h
  for j in range(80):
   t=(L((a+f(j,b,c,d)+x[RL[j]]+KL[j//16])&0xFFFFFFFF,SL[j])+e)&0xFFFFFFFF;a,e,d,c,b=e,d,L(c,10),b,t
   t=(L((A+f(79-j,B,C,D)+x[RR[j]]+KR[j//16])&0xFFFFFFFF,SR[j])+E)&0xFFFFFFFF;A,E,D,C,B=E,D,L(C,10),B,t
  h=[(h[1]+c+D)&0xFFFFFFFF,(h[2]+d+E)&0xFFFFFFFF,(h[3]+e+A)&0xFFFFFFFF,(h[4]+a+B)&0xFFFFFFFF,(h[0]+b+C)&0xFFFFFFFF]
 return b''.join(v.to_bytes(4,'little') for v in h)
def hash160(b):return ripemd160(sha256(b))
# ---- secp256k1 ----
def add(p,q):
 if p is None:return q
 if q is None:return p
 x1,y1=p;x2,y2=q
 if x1==x2:
  if(y1+y2)%P==0:return None
  l=3*x1*x1*pow(2*y1,P-2,P)%P
 else:l=(y2-y1)*pow(x2-x1,P-2,P)%P
 x3=(l*l-x1-x2)%P;return(x3,(l*(x1-x3)-y1)%P)
def mul(k):
 r=None;a=G
 while k:
  if k&1:r=add(r,a)
  a=add(a,a);k>>=1
 return r
def cpub(k):x,y=mul(k);return bytes([2+(y&1)])+x.to_bytes(32,'big')
# ---- Base58Check / keys ----
def b58c(p):
 d=p+sha256(sha256(p))[:4];n=int.from_bytes(d,'big');s=''
 while n:n,r=divmod(n,58);s=A[r]+s
 return '1'*(len(d)-len(d.lstrip(b'\x00')))+s
def addr(k):return b58c(b'\x00'+hash160(cpub(k)))
def wif(k):return b58c(b'\x80'+k.to_bytes(32,'big')+b'\x01')
def xprv(k,c,d=0,i=0):return b58c(b'\x04\x88\xad\xe4'+bytes([d])+b'\x00'*4+i.to_bytes(4,'big')+c+b'\x00'+k.to_bytes(32,'big'))
# ---- BIP-39 / BIP-32 ----
def mnemonic(e):
 h=int.from_bytes(sha256(e),'big');b=int.from_bytes(e,'big');cs=len(e)*8//32;b=(b<<cs)|(h>>(256-cs))
 return' '.join(W[(b>>(11*((len(e)*8+cs)//11-1-i)))&2047] for i in range((len(e)*8+cs)//11))
def ckd(k,c,i):
 d=(b'\x00'+k.to_bytes(32,'big') if i>=1<<31 else cpub(k))+i.to_bytes(4,'big')
 I=hmac512(c,d);return((int.from_bytes(I[:32],'big')+k)%N,I[32:])
# ---- self-test (Trezor official vectors; aborts before generating anything if wrong) ----
def selftest():
 m=mnemonic(bytes.fromhex('00000000000000000000000000000000'));assert m=='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',m
 assert pbkdf2_hmac512(m.encode(),b'mnemonic').hex()=='5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4'
 assert pbkdf2_hmac512(m.encode(),b'mnemonicTREZOR').hex()=='c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'
 s=pbkdf2_hmac512(m.encode(),b'mnemonic');I=hmac512(b'Bitcoin seed',s);k=int.from_bytes(I[:32],'big');c=I[32:]
 assert xprv(k,c)=='xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu',xprv(k,c)
 k,c=ckd(k,c,44+(1<<31));k,c=ckd(k,c,1<<31);k,c=ckd(k,c,1<<31);k,c=ckd(k,c,0);k0,c0=ckd(k,c,0)
 assert addr(k0)=='1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA',addr(k0)
# ---- main ----
if __name__=='__main__':
 selftest()
 n=input('Type a long random number (dice rolls, digits, anything): ')
 e=sha256(n.encode()+os.urandom(32))          # your input is always mixed with OS entropy
 m=mnemonic(e);print('\n24 WORDS (write these down):');print(m)
 s=pbkdf2_hmac512(m.encode(),b'mnemonic')
 I=hmac512(b'Bitcoin seed',s);k=int.from_bytes(I[:32],'big');c=I[32:]
 print('\nMaster private key (hex): '+format(k,'064x'));print('Master WIF: '+wif(k))
 for st in(44+(1<<31),1<<31,1<<31,0):k,c=ckd(k,c,st)
 print('\n512 receive addresses (BIP-44 m/44\'/0\'/0\'/0/i):')
 for i in range(512):
  ki,_=ckd(k,c,i);print('%d %s'%(i,addr(ki)))
