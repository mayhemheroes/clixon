#!/usr/bin/env bash
# Regexps appear in Yang string patterns, see RFC7950 Sec 9.4.5
# in turn defined in http://www.w3.org/TR/2004/REC-xmlschema-2-20041028
# Current implementation uses posix regex(3) which is not correct so
# a simple mapping is made.
# Libxml2 has an XSD regex implementation
# Test strings have been generated by:
#   https://www.browserling.com/tools/text-from-regex
# This is an unit test, not a clixon system test
# See test_regexp.sh for unit regexp tests
#
# NOTE: no tests for ' quote in strings
# NOTE, the following does not match in libxml2 (but in clixon):
# regexp: ((A|B{0,1})A)
# string: A

# Magic line must be first in script (see README.md)
s="$_" ; . ./lib.sh || if [ "$s" = $0 ]; then exit 0; else return 0; fi

APPNAME=example

cfg=$dir/pattern.xml
fyang=$dir/pattern.yang

# Regexp mode: posix or libxml2
: ${regex:=posix}

cat <<EOF > $cfg
<clixon-config xmlns="http://clicon.org/config">
  <CLICON_CONFIGFILE>$cfg</CLICON_CONFIGFILE>
  <CLICON_YANG_DIR>/usr/local/share/clixon</CLICON_YANG_DIR>
  <CLICON_YANG_DIR>$dir</CLICON_YANG_DIR>
  <CLICON_YANG_MAIN_FILE>$fyang</CLICON_YANG_MAIN_FILE>
  <CLICON_YANG_REGEXP>$regex</CLICON_YANG_REGEXP>
  <CLICON_CLISPEC_DIR>/usr/local/lib/$APPNAME/clispec</CLICON_CLISPEC_DIR>
  <CLICON_CLI_DIR>/usr/local/lib/$APPNAME/cli</CLICON_CLI_DIR>
  <CLICON_CLI_MODE>$APPNAME</CLICON_CLI_MODE>
  <CLICON_SOCK>/usr/local/var/$APPNAME/$APPNAME.sock</CLICON_SOCK>
  <CLICON_BACKEND_PIDFILE>/usr/local/var/$APPNAME/$APPNAME.pidfile</CLICON_BACKEND_PIDFILE>
  <CLICON_XMLDB_DIR>/usr/local/var/$APPNAME</CLICON_XMLDB_DIR>
  <CLICON_MODULE_LIBRARY_RFC7895>true</CLICON_MODULE_LIBRARY_RFC7895>
</clixon-config>
EOF

cat <<'EOF' > $fyang
module pattern{
   yang-version 1.1;
   prefix ex;
   namespace "urn:example:clixon";
   container c {
      description
        "The container contains a leaf per pattern case in test_regexp.sh
         which are the unique patterns from yang-models";
      leaf rfc2{
         description "RFC 7950 Sec 9.4.7 2nd example";
         type string {
            length "0..4";
            pattern "[0-9a-fA-F]*";
         }
      }
      leaf rfc3{
         description "RFC 7950 Sec 9.4.7 3rd example";
         type string {
            length "1..max";
            pattern '[a-zA-Z_][a-zA-Z0-9\-_.]*';
            pattern '[xX][mM][lL].*' {
               modifier invert-match;
            }
         }
      }
      typedef twomatchtype {
         description "Example of double patterns in single type";
         type string{
            pattern "[a-z]+";
            pattern "g[^g]*";
         }
      }
      leaf twomatch{
         type twomatchtype;
      }
      leaf threematch{
         description "Two patterns plus one local";
         type twomatchtype {
            pattern "[a-z]{3,6}";
         }
      }
      leaf p1{
         description "juniper regexp";
         type string {
            pattern '.*>|$.*';
         }
      }
      leaf p2 {
         description "RFC8341 NACM group-name-type";
         type string {
            pattern '[^\*].*';
         }
      }
      leaf p3 {
         description "Any string";
         type string {
            pattern '.*';
         }
      }
      leaf p4{
         description "RFC8341 NACM matchall-string-type";
         type string {
            pattern '\*';
         }
      }
      leaf p5 {
         description "ISO9834-1 ASN.1 object identifiers";
         type string {
            pattern '(([0-1](\.[1-3]?[0-9]))|(2\.(0|([1-9]\d*))))(\.(0|([1-9]\d*)))*';
         }
      }
      leaf p6 {
         description "iana-crypt-hash  type is used to store passwords";
         type string {
            pattern '$0$.*|$1$[a-zA-Z0-9./]{1,8}$[a-zA-Z0-9./]{22}|$5$(rounds=\d+$)?[a-zA-Z0-9./]{1,16}$[a-zA-Z0-9./]{43}|$6$(rounds=\d+$)?[a-zA-Z0-9./]{1,16}$[a-zA-Z0-9./]{86}';
         }
      }
      leaf p7 {
         description "ietf-routing-types  route-target";
         type string {
            pattern '(0:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0):(429496729[0-5]|42949672[0-8][0-9]|4294967[01][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[01][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{0,8}|0))|(1:((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])):(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0))|(2:(429496729[0-5]|42949672[0-8][0-9]|4294967[01][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[01][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{0,8}|0):(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0))|(6(:[a-fA-F0-9]{2}){6})|(([3-57-9a-fA-F]|[1-9a-fA-F][0-9a-fA-F]{1,3}):[0-9a-fA-F]{1,12})';
         }
      }

      leaf p8 {
         description "ipv4-address-no-zone";
         type string {
            pattern '[0-9\.]*';
         }
      }
      leaf p9 {
         description "IPv4 dotted-quad";
         type string {
            pattern '(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])';
         }
      }
      leaf p10 {
         description "ipv4-prefix";
         type string {
            pattern '(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/(([0-9])|([1-2][0-9])|(3[0-2]))';
         }
      }
      leaf p11 {
         description "ipv4-address with zone index";
         type string {
            pattern '(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(%[\p{N}\p{L}]+)?';
         }
      }
      leaf p12 {
         description "ietf-lmap-common cycle-number:  YYYYMMDD.HHMMSS";
         type string {
            pattern '[0-9]{8}\.[0-9]{6}';
         }
      }
      leaf p13 {
         description "ietf-inet-types  ipv6-address-no-zone";
         type string {
            pattern '[0-9a-fA-F:\.]*';
         }
      }
      leaf p14 {
         description "ipv6-prefix";
         type string {
            pattern '((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(/(([0-9])|([0-9]{2})|(1[0-1][0-9])|(12[0-8])))';
         }
      }
      leaf p15 {
         description "ipv6-address with zone index";
         type string {
            pattern '((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(%[\p{N}\p{L}]+)?';
         }
      }
      leaf p16 {
         description "ipv6-route-target";
         type string {
            pattern '((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))):(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0)';
         }
      }
      leaf p17 {
         description "ietf-yang-types hex-string";
         type string {
            pattern '([0-9a-fA-F]{2}(:[0-9a-fA-F]{2})*)?';
         }
      }
      leaf p18 {
         description "ieee802-dot1q-.types ethertype-type";
         type string {
            pattern '[0-9a-fA-F]{2}-[0-9a-fA-F]{2}';
         }
      }
      leaf p19 {
         description "ietf-x509-cert-to-name tls-fingerprint";
         type string {
            pattern '([0-9a-fA-F]){2}(:([0-9a-fA-F]){2}){0,254}';
         }
      }
      leaf p20 {
         description "ieee802-dot1q-bridge protocol-id";
         type string {
            pattern '[0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){4}';
         }
      }
      leaf p21 {
         description "ietf-snmp-common engine-id";
         type string {
            pattern '([0-9a-fA-F]){2}(:([0-9a-fA-F]){2}){4,31}';
         }
      }
      leaf p22 {
         description "ieee802-types mac-address";
         type string {
            pattern '[0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5}';
         }
      }
      leaf p23 {
         description "ietf-yang-types mac-address";
         type string {
            pattern '[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}';
         }
      }
      leaf p24 {
         description "ieee802-dot1q-tsn-types stream-id-type";
         type string {
            pattern '[0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5}:[0-9a-fA-F]{2}-[0-9a-fA-F]{2}';
         }
      }
      leaf p25 {
         description "ietf-yang-ttype uuid";
         type string {
            pattern '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
         }
      }
      leaf p26 {
         description "ieee802-dot1q-cfm-types name-key-type";
         type string {
            pattern '[0-9a-zA-Z\-_.]*';
         }
      }
      leaf p27 {
         description "ietf-routing-types bandwidth-ieee-float32";
         type string {
            pattern '0[xX](0((\.0?)?[pP](\+)?0?|(\.0?))|1(\.([0-9a-fA-F]{0,5}[02468aAcCeE]?)?)?[pP](\+)?(12[0-7]|1[01][0-9]|0?[0-9]?[0-9])?)';
         }
      }
      leaf p28 {
         description "ieee802-dot1q-types vid-range-type";
         type string {
            pattern '([1-9][0-9]{0,3}(-[1-9][0-9]{0,3})?(,[1-9][0-9]{0,3}(-[1-9][0-9]{0,3})?)*)';
         }
      }
      leaf p29 {
         description "ietf-routing-types ipv4-address (RFC 1112)";
         type string {
            pattern '(2((2[4-9])|(3[0-9]))\.).*';
         }
      }
      leaf p30 {
         description "ietf-inet-types ipv6-prefix";
         type string {
            pattern '(([^:]+:){6}(([^:]+:[^:]+)|(.*\..*)))|((([^:]+:)*[^:]+)?::(([^:]+:)*[^:]+)?)(/.+)';
         }
      }
      leaf p31 {
         description "ietf-inet-types ipv6-address";
         type string {
            pattern '(([^:]+:){6}(([^:]+:[^:]+)|(.*\..*)))|((([^:]+:)*[^:]+)?::(([^:]+:)*[^:]+)?)(%.+)?';
         }
      }
      leaf p32 {
         description "ietf-routing-types ipv6-route-target";
         type string {
            pattern '((([^:]+:){6}(([^:]+:[^:]+)|(.*\..*)))|((([^:]+:)*[^:]+)?::(([^:]+:)*[^:]+)?)):(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3}|0)';
         }
      }
      leaf p33 {
         description "country code";
         type string {
            pattern '[A-Z]{2}';
         }
      }
      leaf p34 {
         description "domain-name  ietf-inet-types@2013-.07.15.yang";
         type string {
            pattern '((([a-zA-Z0-9_]([a-zA-Z0-9\-_]){0,61})?[a-zA-Z0-9]\.)*([a-zA-Z0-9_]([a-zA-Z0-9\-_]){0,61})?[a-zA-Z0-9]\.?)|\.';
         }
      }
      leaf p35 {
         description "ietf-yang-types yang-identifier";
         type string {
            pattern '[a-zA-Z_]([a-zA-Z0-9\-_.])*';
         }
      }
      leaf p36 {
         description "ietf-netconf-time time-interval";
         type string {
            pattern '\d{2}:\d{2}:\d{2}(\.\d+)?';
         }
      }
      leaf p37 {
         description "ietf-yang-library revision-identifier";
         type string {
            pattern '\d{4}-\d{2}-\d{2}';
         }
      }
      leaf p38 {
         description "ietf-yang-types date-and-time";
         type string {
            pattern '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[\+\-]\d{2}:\d{2})';
         }
      }
      leaf p39 {
         description "ietf-yang-types object-identifier-128";
         type string {
            pattern '\d*(\.\d*){1,127}';
         }
      }
      leaf p40 {
         description "ietf-routing-types ipv6-multicast-group-address";
         type string {
            pattern '(([fF]{2}[0-9a-fA-F]{2}):).*';
         }
      }
      leaf p41 {
         description "ietf-ipfix-psamp  ieNameType";
         type string {
            pattern '\S+';
         }
      }
      leaf p42 {
         description "ietf-ipfix-psamp nameType";
         type string {
            pattern '\S(.*\S)?';
         }
      }
      leaf p43 {
         description "ietf-yang-types yang identifier";
         type string {
            pattern '.|..|[^xX].*|.[^mM].*|..[^lL].*';
         }
      }
      leaf p44 {
         description "ietf-lmap-common timezone-offset";
         type string {
            pattern 'Z|[\+\-]\d{2}:\d{2}';
         }
      }
   }
}
EOF

# Send a string via netconf for pattern matching
# It assumes a yang with a hardcoded  container <c><p$pnr> to work properly
# The function can expect matching or fail (negative test)
testrun(){
    leaf="$1"   # leaf tag under <c> with pattern to test
    mat="$2" # expected match (1) or fail (0)
    str0="$3"    # content string (to match against)

    # URI-encode the string to be sent with netconf
    str=$(echo "$str0" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g')
#    echo "leaf:$leaf"
#    echo "mat:$mat"
#    echo "str:$str"
    trunc=$(echo "$str"|cut -c1-15)

    new "pattern edit $leaf string: $trunc"
    expecteof "$clixon_netconf -qf $cfg" 0 "<rpc><edit-config><target><candidate/></target><config><c xmlns='urn:example:clixon'><$leaf>$str</$leaf></c></config></edit-config></rpc>]]>]]>" "^<rpc-reply><ok/></rpc-reply>]]>]]>$"

    if [ $mat -eq 1 ]; then
	new "netconf validate expected match"
	expecteof "$clixon_netconf -qf $cfg" 0 "<rpc><validate><source><candidate/></source></validate></rpc>]]>]]>" "^<rpc-reply><ok/></rpc-reply>]]>]]>$"
    else
	new "netconf validate expected fail"
	expecteof "$clixon_netconf -qf $cfg" 0 "<rpc><validate><source><candidate/></source></validate></rpc>]]>]]>" "^<rpc-reply><rpc-error><error-type>application</error-type><error-tag>bad-element</error-tag><error-info><bad-element>$leaf</bad-element></error-info><error-severity>error</error-severity>"
	new "netconf discard-changes"
	expecteof "$clixon_netconf -qf $cfg" 0 "<rpc><discard-changes/></rpc>]]>]]>" "^<rpc-reply><ok/></rpc-reply>]]>]]>$"
    fi
}

new "test params: -f $cfg"

if [ $BE -ne 0 ]; then
    new "kill old backend"
    sudo clixon_backend -zf $cfg
    if [ $? -ne 0 ]; then
	err
    fi
    new "start backend -s init -f $cfg"
    start_backend -s init -f $cfg

    new "waiting"
    wait_backend
fi

new "Test for RFC7950 Sec 9.4.7 pattern example 2 (length + pattern)"
testrun rfc2 1 'AB'
testrun rfc2 1 '9A00'
testrun rfc2 0 '00ABAB'
testrun rfc2 0 'xx00'

new "Test for RFC7950 Sec 9.4.7 pattern example 3 (invert match)"
testrun rfc3 1 'enabled'
testrun rfc3 0 '10-mbit'
testrun rfc3 0 'xml-element' # invert: dont match xml

new "Test for two patterns"
testrun 'twomatch' 1 'gksdhfsakjhdksa'
testrun 'twomatch' 1 'g'
testrun 'twomatch' 0 'xabcde'
testrun 'twomatch' 0 'gabcdefg'

new "Test for three patterns, one local"
testrun 'threematch' 1 'gks'
testrun 'threematch' 1 'gksabc'
testrun 'twomatch'   1 'gksdhfsakjhdksa'
testrun 'threematch' 0 'gk'
testrun 'threematch' 0 'abcg'

let pnr=1
new "Test for pattern leaf p$pnr juniper"
testrun p$pnr 1 '$HC8ljb.7d/'
testrun p$pnr 0 'HC8ljb.7d/'
testrun p$pnr 1 '<BKV.+1wnEauL);JDA>'
testrun p$pnr 1 '<n02W\&Mw?(4Q|Q1:m"AJRU4>'
testrun p$pnr 1 '<l"sm/:WSL\]zcR!a|3]m/!?3ue~MueTT4P2k2ARgmm,N0soo+Mt0H1<87QsP>'
testrun p$pnr 1 '$S&)S^4v-K@CV"qG7D2U:hnb6r,75olPgwz6]U$-=B)Uz>AJJ:y`|<f%r(M^_9/_N9AaDZ!Z"GZZYo7HanW'

let pnr=2
new "Test for pattern leaf p$pnr  RFC8341 NACM group-name-type"
testrun "p$pnr" 1 'M,}n[~-vr2Q1Oy\~R#\%"SpGLv B(M+c<C|#V+"f;s&KoE'
testrun "p$pnr" 1 '2]'
testrun "p$pnr" 1 'KrvPY@Z<1@H#k5+&"jZFHt25a\".(tUpF</bMc}0s6:y}&(^SUBNb8Wr'
testrun "p$pnr" 1 '"x 8R\6gxm}VBVg<k*7\"aVAB%dFDt1Yr\fVS?~$s}n$O'

let pnr=3
new "Test for pattern leaf p$pnr all strings"
testrun "p$pnr" 1 '{o}Ui{3D@r-[Vh>13wPu~4[Z+uw$74r/H&j>P{Ct;!"$p=W%UNOtq("R7|p~'
testrun "p$pnr" 1 'p9BQ{,igrQm]:KQ(K>dSfzYb(`E3"V+gUfwJZ:q2|q.6oO@nO{5S&'

let pnr=4
new "Test for pattern leaf p$pnr RFC8341 NACM matchall-string-type"
testrun "p$pnr" 1 '\*' # XXX
testrun "p$pnr" 0 '.'

let pnr=5
new "Test for pattern leaf p$pnr ISO9834-1 ASN.1 object identifiers"
testrun "p$pnr" 1 '2.33086479450833868749097822440514605278281409155812841399736056376657646002078774415765839219672334175.747772845482918.0.0.0.5916448275349606194276362817957343862733955707641054115461774417078988.2325351064280439594345383765941927282529437307150290941599192383781399215521052826484832082871010469.0.0.89598124671891.0.358999960444643059873612179252597803156807399528044098380648712418743408672626.0.7580437145931105986566741548466109530520258263741836406554030384974034019285487.0.985591722687533486362725566.58969768880200733446115394736.0.0.2402876997456431417143715890817878530739131326.8452960357771832867841036.3143767929365488658996516940846605644714999'
testrun "p$pnr" 1 '1.37.0.0.0.94724301615358015104080274979326.98343088306762739738593607280783879252116.813186618718693479637396449027482031842576365796798637831987067116999503531.0.0.0.0.0.0.6965353838702.0.87164650521296003939729415588426122710238356586300265668663344348351127535014278661062753896702'

let pnr=6
new "Test for pattern leaf p$pnr iana-crypt-hash"
testrun "p$pnr" 1 '$1$c9H5Yy9$7Qws6vJaGBv2mpJ6VNSmoS'
testrun "p$pnr" 1 '$1$2$SkiZz2TjAvS3ekAgjlhEjk'
testrun "p$pnr" 1 '$1$T9$/PQeXGpNl/HEX9zbMql.8W'
testrun "p$pnr" 1 '$5$rounds=536671777596140951266141867401009053617894956213119780269981783$H5uT//Hb9o$arftLkezMwuYixLFcfeFjMh2GG/J1yTCPMDgxHqMJSy'
testrun "p$pnr" 1 '$1$ITz$Xmvzj.HRLz6En5gUcqNlIZ'

let pnr=7
new "Test for pattern leaf p$pnr ietf-routing-types  route-target"
testrun "p$pnr" 1 '2:4293476651:65533'
testrun "p$pnr" 1 '7:bC8E28bC3A9'
testrun "p$pnr" 1 '6:72:A1:4A:EE:80:eA'

let pnr=8
new "Test for pattern leaf p$pnr pv4-address-no-zone"
testrun "p$pnr" 1 '.....'
testrun "p$pnr" 1 '012345'
testrun "p$pnr" 1 '259545367681214443027.10350530787058.5443.99627.173558701.1.23488'
testrun "p$pnr" 1 '88.297394474.2588334010...666582693910357647194798912.4696.1889.70.6747042287740312.7490'
testrun "p$pnr" 0 'A88'

let pnr=9
new "Test for pattern leaf p$pnr IPv4 dotted-quad"
testrun "p$pnr" 1 '250.127.114.106'
testrun "p$pnr" 1 '254.252.45.252'
testrun "p$pnr" 1 '4.8.227.252'
testrun "p$pnr" 1 '255.149.90.121'
testrun "p$pnr" 1 '251.148.80.69'

let pnr=10
new "Test for pattern leaf p$pnr ipv4-prefix"
testrun "p$pnr" 1 '242.9.204.7/0'
testrun "p$pnr" 1 '225.250.127.227/3'
testrun "p$pnr" 1 '58.252.126.242/15'
testrun "p$pnr" 1 '5.7.253.210/31'
testrun "p$pnr" 0 '248:197.7.89/8'

let pnr=11
new "Test for pattern leaf p$pnr ipv4-address with zone index"
testrun "p$pnr" 1 '223.142.2.251'
testrun "p$pnr" 1 '254.148.3.254%eth0'

let pnr=12
new "Test for pattern leaf p$pnr ietf-lmap-common cycle-number:  YYYYMMDD.HHMMSS"
testrun "p$pnr" 1 '20190521.131533'
testrun "p$pnr" 1 '90681074.925846'
testrun "p$pnr" 1 '96254578.840483'

let pnr=13
new "Test for pattern leaf p$pnr ietf-inet-types  ipv6-address-no-zone"
testrun "p$pnr" 1 '98.'
testrun "p$pnr" 1 '5dDADCc:b61FBEC5b.eB:FE669be94a5AfC220:8:7A4:Ad032b0bBafF'
testrun "p$pnr" 1 'C:92Ae3aeF5bA60Ff900DEb85b2::7c'
testrun "p$pnr" 1 'f2B8b3eAA413C34628711F8aCaD8b54bd844.b3AAbF0a.8d987:'
testrun "p$pnr" 1 '0Fe4E'

let pnr=14
new "Test for pattern leaf p$pnr ipv6-prefix"
testrun "p$pnr" 1 '::9a95::A54:63:e001:6E1:15/17'
testrun "p$pnr" 1 ':::7:fc:c::eDe:/3'
testrun "p$pnr" 1 '7dE::D1e:8:8eBC::/98'
if [ $regex != libxml2 ]; then
    testrun "p$pnr" 1 ':29:F36:6:46.53.251.2/100' # This does not work w libxml2
fi
testrun "p$pnr" 1 '::CE2e:A:AB:234.220.225.250/1'

let pnr=15
new "Test for pattern leaf p$pnr ipv6-address with zone index"
testrun "p$pnr" 1 '::dbC:b:52:bae8:251.252.252.221%eth0foo3'
testrun "p$pnr" 1 '::A:CeF:1c3:EB1e'
testrun "p$pnr" 1 'F68:c:205.252.206.250'
testrun "p$pnr" 1 '::b:0.251.243.241'
testrun "p$pnr" 1 '::A474:5BD:B::%123'

let pnr=16
new "Test for pattern leaf p$pnr ipv6-route-target"
testrun "p$pnr" 1 '0BD:1cD6:be:dEc:d:4:249.250.71.251:65517'
testrun "p$pnr" 1 '9:efBe:A:d::3c:::65535'
testrun "p$pnr" 1 '11F:c4:B::::::65501'
testrun "p$pnr" 1 '::2d:a:233.36.254.155:5'
testrun "p$pnr" 1 'b6:8e:eCD5:46:Df0B::d50:65534'

let pnr=17
new "Test for pattern leaf p$pnr ietf-yang-types hex-string"
testrun "p$pnr" 1 '5C:Fd:b9:aC:FA:Df:61:48:fA:7F:25:b7:Fd:ad:6a:Bb:6A:99:bC:6e:fC:02:04:D8'
testrun "p$pnr" 1 '5c:4f:2d:b8:6c:89:62:7F:fa:C5:aF:0D:67:0A:03:4F:Bb:BA:c3:6B:5E:f8:ab:eB:2F:95:74:Ef:DD:6e:2f:A7:C6:F0:4d:a3:EB:32:Ba:ab:FF:E4:D8:eB:F8:0c:CC:DF:60:Cd:AE:94:fF:5c:03:79:99:fE:4C:76'

let pnr=18
new "Test for pattern leaf p$pnr ieee802-dot1q-.types ethertype-type"
testrun "p$pnr" 1 '54-aa'
testrun "p$pnr" 1 'd0-7f'
testrun "p$pnr" 1 '7C-C7'

let pnr=19
new "Test for pattern leaf p$pnr ietf-x509-cert-to-name tls-fingerprint"
testrun "p$pnr" 1 'EA:32:e0:3F:3f:1d:93:29:63:DF:0E:3d:64:a5:CF:ec:f0:cd:f4:fc:7A:bD:6F:dD:C8:F5:bc:0D:5A:73:eB:2f:EC:1C:Cb:8f:5E:53:F8:5e:ED:eE:D8:34:a9:D8:f0:95:79:E3:d2:8F:24:0b:8c:E2:2B:8C:c2:4f:Ae:6d:91:be'
testrun "p$pnr" 1 'Fc:f5:DA:Fa:d6:0C:e7:D6:D5:0b:90:7d:5b:3b:e2:dA:aB:4c:aF:bD:DC:46:E2:FA:2a:e6:Ab:6b:42:29:Ba:fa:0E:97:93:DB:d9:E0:36:BE:c5:e0:Dc:7a:b5:81:2E'

let pnr=20
new "Test for pattern leaf p$pnr ieee802-dot1q-bridge protocol-id"
testrun "p$pnr" 1 'f4-b9-b8-ee-c2'
testrun "p$pnr" 1 'EA-63-19-5F-B5'

let pnr=21
new "Test for pattern leaf p$pnr   ietf-snmp-common engine-id"
testrun "p$pnr" 1 '3B:EF:F7:e7:ee:4E:2C:cF:Da:0F:92:E6:0A:cb:3D:32:e7:4b'
testrun "p$pnr" 1 'EF:a0:b9:b5:bB:Bc:67:b4:48:30:C2:2e:E6:Ce:aA:c2:D7:B7:36:68:88:Da:61:aE:A3:20:16:e2'

let pnr=22
new "Test for pattern leaf p$pnr  ieee802-types mac-address"
testrun "p$pnr" 1 'd8-6E-11-b6-dB-3a'
testrun "p$pnr" 1 'cA-7b-fc-1a-dF-5d'
testrun "p$pnr" 1 'd3-eA-9C-00-8A-dC'

let pnr=23
new "Test for pattern leaf p$pnr  ietf-yang-types mac-address"
testrun "p$pnr" 1 'C4:9c:38:fF:15:9b'
testrun "p$pnr" 1 'Ee:a5:da:D7:F6:1D'
testrun "p$pnr" 1 '0f:f0:Fa:B7:A6:76'

let pnr=24
new "Test for pattern leaf p$pnr  ieee802-dot1q-tsn-types stream-id-type"
testrun "p$pnr" 1 '0F-db-A4-04-6E-4E:43-C5'
testrun "p$pnr" 1 'f6-D2-4F-B7-8D-aF:88-F5'
testrun "p$pnr" 1 '52-68-e4-0C-b6-b2:1F-f1'

let pnr=25
new "Test for pattern leaf p$pnr  ietf-yang-ttype uuid"
testrun "p$pnr" 1 '1BFe3fb3-0a9a-eE1C-ce17-baaB68C07352'
testrun "p$pnr" 1 'BB20102B-3CaE-2B67-EeCc-9f3a44aCA1dd'
testrun "p$pnr" 1 'DCb3Ce27-0F2D-02ca-38b4-C810Be3bf4c6'

let pnr=26
new "Test for pattern leaf p$pnr  ieee802-dot1q-cfm-types name-key-type"
testrun "p$pnr" 1 '2W14gril.aQjw7dCNh0gqAnZ8KuDwuV10XhgKEDKgiSEBCM9UqLCnnfrDVr1kir3c'
testrun "p$pnr" 1 'ILgG4J1AJeE8KUqy9zD2jSy79EJcMmWxk6gP'

let pnr=27
new "Test for pattern leaf p$pnr  ietf-routing-types bandwidth-ieee-float32"
testrun "p$pnr" 1 '0x0p'
testrun "p$pnr" 1 '0x0.0'
testrun "p$pnr" 1 '0X1.P'
testrun "p$pnr" 1 '0X1p+'
testrun "p$pnr" 1 '0X1p+100'

let pnr=28
new "Test for pattern leaf p$pnr  ieee802-dot1q-types vid-range-type"
testrun "p$pnr" 1 '843,8,819-396,843,35,3063,2677,63-44,58-666,2,79,80-3451,72-2,74-6,316-7361,1-8248,729,1829-206,5339-89,2189-801,9,75-2357,2172-175,8,73,9-5,761-14,665-5277,22,51,4-10,86,386,144-135,21,4,9538-259,7751-85,2-2,9926-92,68-6704,73-261,678-4,62,94,3-20,8591,5,538,1-39,6,4-966,40,27-280,6-54,50,9003-78,5089,3053,400-2,1216,999-61,312,53,1777,964-911,1-17,40-3826,24,5,1079-1,85,8142,125-5,2124,43,37,3631-6456,2,5620-9,2-9195,2825-94,577,70,4,80-5470'
testrun "p$pnr" 1 '7,7-1,5-6455,534,602,12,409,3,451,71,8519,749,787,258-37,858-12,136-5454,850-4,5-34,43,38-5101,11,3732-4554,5,6-484,9312,594,731,3,5551,69,9658,3464-86,9-3,9-53,78,12-524,6747,313,599-80,9,6-138,6-8867,6-853,73-9,804-83,946,702,5839,710,23,519-945,5-21,323,6032-7,7013-51,7743,206-8463,7,91,44-85,290,2,398-2,89,1-7625,8395,133,545,22-9,54-1'

let pnr=29
new "Test for pattern leaf p$pnr  ietf-routing-types ipv4-address (RFC 1112)"
testrun "p$pnr" 1 '226.#(gmk(%8@!$B>5^:WC:Mz|xG<LiXZ|'
testrun "p$pnr" 1 '239.0lUYggpvHP'

let pnr=30
new "Test for pattern leaf p$pnr  ietf-inet-types ipv6-prefix"
testrun "p$pnr" 1 'fGE>WUT OC0z&mQ*$1>zDRI]e}LMK~Cs%Pi[=>5f4hq:#,(,]~kb{ScU\1|7SreM:k\i/e@*vDvAy[8dw1m)$*; 8O:+<R%!Qewb7DuC U%*+&"{m(I+>_{`)[[!BM(II6o:}"e-WPgJ6??)q=@_KB[Sp f0[UfyuSqB[Ze:8{|IU5[ek(r^8:,x)MdCl&u9U(M;[N4U1&#"s2ZZbo:M9$C^$jN?f,8LUO"n(/cZ4G`o)iPH#OrU.go{{.i|W}mQ&w;gLztX;U]$%~*vYcx%QgKWO=,j?UR3L;cSK'

testrun "p$pnr" 1 '"wX+Hv}WReh_<nhE!U{me3r%56YkX&j?{k:"MOP]Ys;K{SlVpBxv_.uw1v.W?~R:~meK!!:h2:@YlI~-`NI$0&SIOOz9 De)XcGx3s-Ht1F2D+[.5_1upLc,Pf,>3!EcJ9CoY{vhlCQ 8d>01{mes05.a{c"nh(\8P2Y:#;"Je% vi5"`T3- S`i[0G"=P^Mga.?~~NFzSkq5!Zmfm?BNPTW_{8Wx1:o_0Ty01bf(owqEn8l"xk9]+m,0zQ)+)PsBo6&!wgNZB5,E-mmJ+cT2NjXz6e?;L/Q+cVEB"8r<4>Wz8tZ:arPX${Tg]<x1~g%iJK#T, YmqTx~b "avkj#{7Luc+(`i|}#*=j'

let pnr=31
new "Test for pattern leaf p$pnr  ietf-inet-types ipv6-address"
testrun "p$pnr" 1 'n-Q+1{+#[./ye;KApCl;:SX/X1*pk4\<AlN3T:W>|2 S8p*ku"/qOMjmn+<Z% goJ>j2&fZf%6Okvo<MDZ:><FBb$%]3B.PS")1GbWien?F*i6GX}34dD83M& :rfnfyz<}*o*DBpm5>gl}4]||Al{Pq[c}Era2TN4=kP-\9wg*So[xG;V)>g42#:0-b3:h[yF-O/T{}[f-f$hFK.05cjAvHFpZVA8z.d7BD{;-|_T8C8L5Gjp&*e"Ex '

let pnr=32
new "Test for pattern leaf p$pnr  ietf-routing-types ipv6-route-target"
testrun "p$pnr" 1 ',qxl*+)mvco5s)m,qbXzK!01BzZIXH_h8owQ:Ou\x]ki[gFZQlkX$%c_{>?>La!04`A={guXkh8;)^!jTv}j$$L9&b9)rSHmPHgWYOz\_pt|3TJ:gs$L^WPUF^5S?}2llC1.Fw~So%]vv%z@yQ1r^9sK&AR~"YqQ~;}2D:K5"kJ#%:&xb;Q]"pr}9\dv(S|FZI+GCqB3hAK1.$4C^a-_e"8@xQNi`.;]i;3iJbnhWSvP@+M<nAd{$=@M"sFRkKi%|):]-jS3EYm!04!+FOHV]it("]VIx(aa.?bvE,6Hms XsCF2hALJLXm]NN:Ua&+B tPBUCno${z^d`GJ!EHhg8DU31steIJ*Z_!N~nylUnJwJxqxRc)*E]G;t"}UJ=[WVzoQtdmNT>3("VW&,"7tC:2|8=y)]>%0"G`,BG"NgXL7Gh6 zQd/*3\y21N19\XfoO}Q"*}2`*.:^ic"]E`2JceD@QSaPOVPZwR^}#aKDUL~.K A>FY{f/vb(wz(),H<"VoLOX":XC~HkK 4Fzh3"d@tIYNGQ6$cXgKeiP+?1m)~sN{0:@+[%|$-`$,&(W+a"`_>6-dmZfCs8~&u{fW"#AL,?X|#4Om\uV+#o)[]/FG4/.Nyb~WL=eH$V15yRFk%i0`~}kVFweD];<]*v!Q:",y\PJ_h:<XF@g*=inLuYQ#1:9h<t77b=1h&yX[K7V8"xq#X|pP;;>1c7MM8/qMQ)@3P8xyO6RV!|>fNW0rL::8GQn6iA$z8b(= =VaY]3`|Fs 9wtli-(\AonWeAqhVR_<Ge^0acAO%o\3D(sDk+_v 0K(.Oo0)!}B-)>~LN;1#F_"H.%")XIpG*:aLY=OF.`k&7om ,@^&ZU#oq]x/ =A)I<}Ak? jzP"4.<Hke#$P[W:PN/D4os300)^ 6KkTL_~A+&*tSHWjej3 WA!N0!`@!$xrhWL 7;oteKled4&%<3^8kf_NRg@1v."puya21$9eu%V;V$HKGei!:Z `2|9]9OOKOY!m1OM#y>L-zg7"/{J<~"pb6)E`svK0%,lQ:kuvaq3d8d5Hl(?EF?~Sy|<L9Li%V5r@97T-T5KSt0=zI^,.N0-sZ+5e^u$t~au{nfq4|Dgy1>Wb_?Opdex`l;:}zokWC4FU]"^Zaztd6^8Yjk/vmDSRQaVG!N{dR\GuH:RZq"@n%,xu14d" l#y<~GvX}ZUz2>6Y_XfeJlBt)h"*ZOJM6E<[~vd{xI?:lqP{tmQ;.|yy~2C7~vB0Ok):`kp5qowvp:.AuNWVVi*%I!$W B"4phH\g6<3]+o4qc+(l8b9R}eGs PaT,\Y(PtmmH!z*%AtlO:`3&5c:*%VZA0jOCp(OMQf#<Cxp91^DSTVX%DLThwDly@-NUh(L-1Qa-!y?2YRN480wHQB7E[uywQiH:"@>]?}PsE5%]"oapxBM8,}?j`wD(AHSKDHnK<T5DPK&rw^pPuN t9~A*|_4IV{+#!{"ME{**g?#nb;M9O:[3#Lz"U`5Jz|R|nf)FJBZZ$CO6*v(8A:bhfX6${d [p>Rbgg!O[_V*%T&hN>28JcS&XZC]7)|cIlL-<V4>%:lDc]M{\)o_<$,qkr"B/UrS(<.?t#GGiKsN}/>_s[9;_D,mX>+urfK`N}whWrCGusu:%_<%iyEF@@"oG%D1lk>/FHQBX+0cPt^Z. BgwmF&g_:~\ )]zqD nu/p[jw^#ZYy1I U4KGZ<+6{b8"Sy|f?j]xuXYYH~`g0q,qUO\TZfpj7K>"and"6`[`sM0P]:Pq</&co7dL"^"l5k+5-hwNl~ 7HSYMXNb*Z!D#j)A%3{A]VVv9$3\fMDt9`rtS&zweAWk:-"Yu{ydWkyo4-bLRG7F2p9Er{rmS;7CZiX@]ZF/C0gT0Zu:UMd=lQ^pT"Zs`AD)I=E:^2b$m7%9#Ag0)"sAZ+F[a!!nA_eJZH}+uL`4yDN"K7MvDDIYJDXsd2[XDrr_&Y138_4"UqcIdDZ]+VP&`tbA@:h[o)3tz.`j~zr&z](1Ofdlq,fwE:&7-j]Jqzi](](.i\\RR7N)Z/}~C&&"TezEY6=R@w&Ta>!0i!S Mq7deA`v8`<.<v. :U0#+sZ!"@?24d*@pnSr(1z$Zil1P|)LDTSn[J0e:HNgh&ImpK {UAOk4!&oTc11F+r_[G]|&AD-uhuCDj=*~<b51D4>C}\y:BaoBaZVOJ"]zIrvrp(30mAE^YL?eHu{Uhw?tp`&&4#?ziFiid:=<$8!&U)?kTp@htZ_/%"f}pn0&aExA[-c;PV|LCM[P$c\:;Tg5("nTlV*!(7HIZ_qc<=Hum9`qqfz?~O3IbKz~|m6-k22HceKP}scTOwz$LAmFsQ(dQ|SiY)0:f"l);?IAp0>WnT,~l"Phvg8H8)t./J[f/ D+!coS!=<Z:WI;?mE6^QIz]==9O,7C06D=oQG921et.4FEg0m/$of=9Txg1p{W \3KIa^B+u=70?":YInS~[~Bc+W|r4=@h~NelRyh[r#U7E#0O[DB/&`#"|qyGmOL@=<0a,o8;uRCH(m7t{,KwV^"\uQ)Q0}%DW2HogQy%:WKnb[j&>)+#>#!U1Wy-\Ejoe=js3$S"gW/9*aTn>W$fHZ:)x52AUIeK#s<yAr}>lsM"5KjT!1-*\ye_}KfU|=8w8>\nV@naj)Z.:.O"lV{<;c}<[_>|#32tFG&![t,[10]L7VSv%+84>V(,"c"2*yD*3n:qS6533_1w:B)6iEq\N:$xpB!5r$5I}aT{G+{*&6X{g325T`Qw_5Anz2J=~Xq}puOu4S4IW23gV)GqfP4&9sJiL>af,ap<:EF;R:!g%w;H7H"ZvS.4]"i}&_#h1#w1ghwD)5CZ#kM5jLk&?sD^x*c|1BAQtxH\`@@|Hc^CqRr~J:q[hjybEt3*&T)|p]&)nGc@qG;H?;_lJ iQIs0*5#1bwUnw;2|Nrg,8W9z@|51Nh%,/|#Oc)5rz"lDWi:k~8XyekfKtY/` ]eL gOFRk{5q`QGWp>(6MFsF\UNKx7{,D_oreG`(Pr^e*zuA:CbG&o,+}{]Cb_PG9dk5P+ qg{.zO+&:ZmbF9gF$h;ahN:jw$[?Z$l]1wLg`ll}X>*<HrIWDF*IyLgZ>53KtB2i_u0JvbO_RT)3]MOu:~mrdLs@"RQg*w)ou?yJ)4-:x2;N?\#??I(q^7Nfw`U$gU%-kv+TGe0<1+JEdj1-DQ[a[(kE!:|D*ST70>K*tNv|4+)MU2Ux_61[tYprsKKn(f5qmmgF~gN`$"EWT6;DZ}7F|M?KnF?eAX+|/?d4Gkljkn!Gg_qMN^7|#}Ti~m8:PDl@q:^#W<_otlKw\o^<Lv[Rzb]Ck2o4@S&$hFe|;!;:r=,$KAbtk9Y4;9[U$\y)px6_P`)IinNyj@eNOds6j:3<nE|xOs/V!FPl-(&64GTtz)U%UXNz7l`821waEzQqr3c?`KBh&O6%Nhv!Wl23_?Y#j R|R:e?[B$e{*GW\L*vzc;RK:+$$ZwuuagyNg;n_k.n"9*SA7c6a"8{oZvm71|N/T|cv~bzlcJ(%%X`$Y/+\irF1_yGE_K#uDW0b6/DtxV*AE!061KT*hj<:!!yY6,W6<Rkrpg%o("c_"Ebv3An;VA=`pQu?SwB++yeZ[k"~QW$ua4;$YW}_9RCyxE9;LhZf4!_T60&;s=KvX4y< :+"P+JP!z">*)@UaCyb-}rj"[aH!0+IEoAMamIyItEUt#+s}DGJJl1:j|jb|KuGGaF7(?_x""N(I/88bjf`S4nWaIM\eDZ<bkXPRoO&<3P]5Q)+`l}-wzeLq[?uNvMIo\2dRMol\"c8>:%;+l9W7Y ^[vI>G>*$Omt\Mz\{?oaon\b4 3&=x}gUQ$B;?ZSB6|fxUa]1@Q!EFA])l*0%(ReJ~h&4:+~Mp<Z(n!`^Uz+l1CC73O`;hTaXz(#ABOEiUb)kQ* b7!t6Xe21(Kc"&%KS"?ArH\iX.+>3#:Ri/z.>1m&#-(I))ZjN?JUmV5HP\=m9)j?Q3;9Byo#}Dz7g"A`tp:N{XYeTKW>q=R.f9!hFW?x*Cp6qbP%eiM_GPtW5Vl{#b#)xP2{[lvPm`2WWju8(h[O~,{ril1YNbp)6nu/qeZ6@f^:Jo 32m%|?.(&l9\WvAJ3y{f\a6\$1}vEH%Kk 3?${uzv2wGCGLF]1AyWgI|-J]>2dH$REz?[_.^:#e.t*,C,\QkIJ"\OFuw{cz[5lDx`"Nq2!~;QLOEKZwSpuzdN9:Ix{"f$(WXmWzQCuEdd857@*)TSQ_=xzk|<NEgosMYUl/TpDQS5:~2*I/k7 R?n%^3}ne}iF%Lhc7]6@dYoPF E_-ktoR?dC=.*l!KE&ez^~77S(][Ti8q>e2LoWt^VkSrMnx"gMos"(PU<9Zl:32dIDO&262vx4_dIS}h5:VG_h}nCTa6Hw`%[hl{l]g((zZi9X_ u<0{UiT$g,).kI6$oqA@r#U`iI.(G@7>#Ax[CgeZg1k *&->Z|vi5c((_p!_mA:)CP}WFctolMk*Doun,mU-2[~:xVODrn;4lnk*Zrh=yHh$wPd{,"&,4TlT^~V$8:kBF6DY!~":;4bNOR;k!$0W<~ka Iuh?><&_\fLbr@Mz6btvkXh\Vonc<2{Wv1SIAK9<.#."#ul^q9MCpKKa`9la?ke8%f:BDYrhbrpN(X[(XSoL\4qY/vu@-6.q([Ju"!d/A&dS2r`T@]Ggmglf[wo}Ts@JI$W:H"YV|3!!KN_]12!okEuSj%`O/n<^&hNBo6=]bhv`qk|G%K7i<66Z!bB{G=X7jizje"wM1$x^B4hY+;Dl{&Oz$<uTj:e_UKoY`m4@y.4-zh:"MdE0g/z2swIN1@=^"~m&W3&WpBY~N_b3)""mgAi]Qm!kFU$$hb:uYf)N{ug?PX?e1J1y="P"$Zq0)+x+84v2d_G^n dY*N6b{n{ #.otP3\^_Qboo*^.:[9~9Z$7*i]2LEF$6G3jB[jwmtCkn]"G4dRBsS~,litFQ{w:]|BU(S/k1tC;Q#a&gVmtt HH;r{><<v)Tj@LOLC6DhrbC4:a;]$<X~\SV3%}cI]KIBHqT2i/g,q=Sjl?TEx"<}@=47:h~_Wjf%,Vz."dT tr<J8F@5.ylU/G4yq"/IAA\S8JMA@q#FcbTg9o/]"=l[T=g0sx4>msL%_cLg"hY~f}{+6;"+LyGWCqjai\:!@tpnb=xCJ*u}p$gU(n&lW"~Xc0e5\Yzdc5NiW~&HtDeV3k+7"qh.o+x;l#NZGZN >3izBhVp:[|1umG~ v@p\+vC,&RdeBJcs< 8e|akwt:(E>\K-3y:n-i6~f5p.qvYYw>C*~{gmL9:EMWSKbMl}+K>tKs}GODS>\1ea67*-~z7M?Zp<) R,-fL3&1Y1?jryaIvSurJTVN)Vp]i*@@0t}#mK#m"q:hD/gg{@ ^R,]|c{#t1^9(7zePoGjlnBm(>x"Z9zjuhP;c#~n$U2hy85&Qng/%P"d"!P#U!T_f4_+u]W:$f8xkQ9W8Y&))>"Cv#T:"9%~C))@7p.Wo,iKtntQwT>oh%Vf"5*zFR]rV*t^,9@}M*# ?KAimV\[Vvh^:*\c,TE73r:hLkx2O.Ac-3ooF<N%q{+fi 7v"VBH}PCH8&_UH"{S#j:*6@Xp*SX ;1;iHE_G\:I6GxztO[m0l((Fx -YpDPzJ*FcA>l&&.*H2y|P6M%&>c$8e;[,v4]Kog:^?{;kjz0eB@1p1-p.CK,]5r1W/08S,9te?#/7<\8.`9\?i|5O%8zCsT0`KVLJ+=~,fouP.~)YqtMVxPjE~(HpMj}>Qu|l=}`#1~X:ii]cj|8bZDi}Wq$v|nOS9S"\=>Sn8W"$b,2.[Z. eq3?y8cH(5Mz~0yFoOD/m|}eL<LPcitA:0'

let pnr=33 # 33 country code"
new "Test for pattern leaf p$pnr  country code"
testrun "p$pnr" 1 'MG'
testrun "p$pnr" 1 'JT'
testrun "p$pnr" 0 'B'

let pnr=34
new "Test for pattern leaf p$pnr   domain-name  ietf-inet-types@2013-.07.15.yang"
testrun "p$pnr" 1 '.'
testrun "p$pnr" 0 '..'
testrun "p$pnr" 1 'X.g.Mkx_uFR7vmAZGQhG83xK99SCQOh8keIgu_XMclzDtTJp9cY14Bm1Z1.Juir4hmn6WdLQW4JJ9PgBdddUqpExmMt.gh3gKToSNaXjCSoqkt-D8vdRyj.Y38UI03FwouxvtGD2_BK-Hrd4AxA.c.n.f.B.x93Oeev6nSSdUhdNXWptyy4zcjg9GyVutcNl0cG8ZR1s5A0Mo8Udj.oIA9fcuDCJrD2lHBZxjjP-JYCj9EoTrv6Ms1NE1eQe1-JAgj2xmg2JEI3T8NrS.FO0WNwvFco8tNHuO-cGCpynzGjjCxyF6-to_rN.W.m.e.QuXsERkVIwqmegRM5.sgu8SFaat1bfe6Yy_zyA0ik1KKuerKzydULGooC2-dR-J_ISnLchZl5bGuU.hhy1Bi.J.X.i.j8tr2xR.8rDKG5DO2ZIrGP_CMe227nxLD.J.5A6QRfaXEqQ9GtxDQ-ftd4vwru9JpkYUeD7DGOQthCdEY.QrtN41h6RjlTd-ZLWBeMv5Fx-hTfIraYFUG2f8N6v5GJH8CDpWAr9gSRyADXB.'
testrun "p$pnr" 1 'bbvbknMkNsUFQND3WrD6dztdxRGiMOD8NilS-frikGjH.Hey2ZJEVSD9.2.mVfAHwdBdciaLsuOkM4erP9.yNz_5zfE4oyJkehfvnhQXwHDEoFkj0CWm1Bx2iR2WVNS8K1N_8uJHdJ9t.S.smiBShNr.lA4rZiaQXTmZXyaCmUe33vb0f9ymkgg3d.NA5GPs3j1TI1osHepzohGc8ady3m1Uv2WIwaDj.re_MqDbbKdhtlGulEoLWVR2tVkh6DvAectPd.b3ZERO9ZLraQJCpIkCxHkwVTAO0W0k2kuXVtwB.lxHgNOVx0jZYbwNmHZfi7Q2V9y5LN0HKQwGscrRqSHPTVqN0Cmh8mkbOCZBw.I1TRQAmSkipTN-gNfn9qcoXfI-IbXWTDGucsg.u.zn8GaTW6.nefNjW-cWt8Fs5lWDEMlhHK.x.Y.6kBc0bAJZhSww4qy.WeW9FF39CSGu4LHWjnq6pgH65bWNIfe9R8ht.Kj2DERCmq2p9BVNUddJC49xO7FyweeovgsaN9q53sRQfuc.w.bQRIipMkKiK1ua.UDH7JofnTzCvL7Er5OHo.eq7v4Pr-RFmq-zGhEGrYpSmxCqj8CKtFN0We8J5dLX_samjVdE_d0U.v.AlHcS_4.0.QaSGGYW5fPbkm7nrxn70fEFalGgDu6UniDA0Y4apiM9UYtLF.E.J.4OdiDx-Z3KIGeuWLwR8WWg0q67vtwsBVz6_q2M5T.s.3QZBhgcA86eTH40WPSA05GhtUHKvLwfHHPpCR.RSHf4CjAR_WZpzTxoZlCZTPaGjTyyZMTgSei3DpBVso-8pE4h.7.9.UN49ix7wRsin5150Oj-XTfBXYLGB7lwHPpA3hfqUVru9zTTiiqqWmz3wYsfK.HKnJi5e-J-Ysef0Pi1En8kIoAo2QN8NzOPN9RBOeJcVRkyp_U4eGWH58TSOSnj.XgyC_NUD_yt4qaHHqHfORi8a_SLpZAOhxrkyaW3.4Eo3wrDWvi-z9QW7oURyL4mlr998nfpY1k24tWkf7p_XhkRql.55oHyAypTVUcWx18yRwS77D.JhQO343A44oXiVPCMBk.K.d.q3bg.a.eRd.tOTx.T.G.8.OtgGnaDz9EuECam8b_INLJey.N.WeRJ.a.4v4T9PVgPYYoN1-03Ah0svlX24D2k0NuyCPCYpYK8tCe4uNH4Zbl9Jm_J.6.q.9yo34TDdOgcJF85--pQgNgA0iGdkaZB.1.oKe4TjgCpG6bMX3H5-z25cTgTV.M3VsCtycomSKxFgp4VDOWF-qtW1_CfsUD7NAvCHXuRtuMRX.z.I.R.kK5UmD6oRbUetMVjejHbXn1X2.aPZQKQys.y.C.u5Pgwqaw'

let pnr=35
new "Test for pattern leaf p$pnr : regexp:$re"
testrun "p$pnr" 1 'hlBYbOGNzjQPnoCfdQ56KGwME8T1Wvb69MYdp43d_nz660eWFymsiLZFApiV6Ekeq96Xk5Brum'
testrun "p$pnr" 1 'w613PTt2'

let pnr=36
new "Test for pattern leaf p$pnr  ietf-yang-types yang-identifier"
testrun "p$pnr" 1 '28:12:66'
testrun "p$pnr" 1 '47:52:09.76736863019161642481445701650'

let pnr=37
new "Test for pattern leaf p$pnr  ietf-netconf-time time-interval"
testrun "p$pnr" 1 '0311-28-81'
testrun "p$pnr" 1 '2412-11-66'
testrun "p$pnr" 0 '1431-96+63'

let pnr=38
new "Test for pattern leaf p$pnr  ietf-yang-library revision-identifier"
testrun "p$pnr" 1 '6950-61-67T38:43:96Z'
testrun "p$pnr" 1 '8988-74-34T57:13:79.15719206374337876678225281560675720112932883235811143820116778095747930611536117-35:64'
testrun "p$pnr" 1 '4778-62-75T53:33:25Z'
testrun "p$pnr" 1 '3434-21-55T08:08:92.079051721917647951806003119850774224547876422700593012Z'
testrun "p$pnr" 1 '9757-95-60T60:67:93+81:80'

let pnr=39
new "Test for pattern leaf p$pnr  ietf-yang-types date-and-time"
testrun "p$pnr" 1 '043.4.015390457'

let pnr=40
new "Test for pattern leaf p$pnr  ietf-yang-types object-identifier-128"
testrun "p$pnr" 1 'FfD6:fF82:Ff01:ff14:FF15:ffFd:FfC7'
testrun "p$pnr" 1 'fFDB:Ff5e:ff3B:ffBd:fF24:FfAE'

let pnr=41
new "Test for pattern leaf p$pnr  ietf-routing-types ipv6-multicast-group-address"
testrun "p$pnr" 1 'u`x9I^26:S_/jO/i%fhHdZ'
testrun "p$pnr" 1 'G#UifDU2yf{MLgo`2bt;j]Wumc55`)ummeX8rq~s\tpj1vWY1#~oe"*\JM<Pms'

let pnr=42
new "Test for pattern leaf p$pnr  ietf-ipfix-psamp  ieNameType"
testrun "p$pnr" 1 'VB'
testrun "p$pnr" 1 '6#>cT\4h&|%!<=pvcjA"E#]q<V\DcK1x^J#+AC|Khi-gd'
testrun "p$pnr" 1 '@[k`_=yHj@Lp&"`R5v+"W!EgV<>]sFukbfW*'
testrun "p$pnr" 1 'SKXTJ,Xnl2fs5}t}aqA7rvB~4PmWpw8e#^32DDuiSW^c:dz1g&'

let pnr=43
new "Test for pattern leaf p$pnr  ietf-ipfix-psamp nameType"
testrun "p$pnr" 1 'qZb/9&?SF$,Z`Gc5Ys@;L_QAo<0|\Fd7;n7A&NO5AG8`792On9w"'
testrun "p$pnr" 1 'E'
testrun "p$pnr" 1 'rx{z5@<uf4#COhDhF DbxnEgOMxQ x%'

let pnr=44
new "Test for pattern leaf p$pnr ietf-yang-types yang identifier"
testrun "p$pnr" 1 'Z'
testrun "p$pnr" 1 '+27:32'
testrun "p$pnr" 1 '+12:07'
testrun "p$pnr" 1 'Z'
testrun "p$pnr" 1 '-01:38'

# CLI tests

new "CLI tests for RFC7950 Sec 9.4.7 ex 2 AB"
expectfn "$clixon_cli -1f $cfg -l o set c rfc2 AB" 0 '^$'

new "CLI tests for RFC7950 Sec 9.4.7 ex 2 9A00"
expectfn "$clixon_cli -1f $cfg -l o set c rfc2 9A00" 0 '^$'

new "CLI tests for RFC7950 Sec 9.4.7 ex 2 00ABAB (should fail)"
expectfn "$clixon_cli -1f $cfg -l o set c rfc2 00ABAB" 255 '^CLI syntax error:'

new "CLI tests for RFC7950 Sec 9.4.7 ex 2 xx00 (should fail)"
expectfn "$clixon_cli -1f $cfg -l o set c rfc2 xx00" 255 '^CLI syntax error:'

new "CLI tests for RFC7950 Sec 9.4.7 ex 3 enabled"
expectfn "$clixon_cli -1f $cfg -l o set c rfc3 enabled" 0 '^$'

new "CLI tests for RFC7950 Sec 9.4.7 ex 3 10-mbit (should fail)"
expectfn "$clixon_cli -1f $cfg -l o set c rfc3 10-mbit" 255 '^CLI syntax error:'

new "CLI tests for RFC7950 Sec 9.4.7 ex 3 xml-element (should fail)"
expectfn "$clixon_cli -1f $cfg -l o set c rfc3 xml-element" 255 '^CLI syntax error:'

new "CLI tests for two patterns gksdhfsakjhdks"
expectfn "$clixon_cli -1f $cfg -l o set c twomatch gksdhfsakjhdks" 0 '^$'

new "CLI tests for two patterns xabcde (should fail)"
expectfn "$clixon_cli -1f $cfg -l o set c twomatch xabcde" 255 '^CLI syntax error:'

new "CLI tests for two patterns gabcdefg (should fail)"
expectfn "$clixon_cli -1f $cfg -l o set c twomatch gabcdefg" 255 '^CLI syntax error:'

# NOTE if the following two are swapped, it fails, the reason being:
# valid "gks" is selected as a valid (expand) match although gk is not.
# this may be a CLIgen error but ignored for now
new "CLI tests for three patterns gk (should fail)"
expectfn "$clixon_cli -1f $cfg -l o set c threematch gk" 255 '^CLI syntax error:'

new "CLI tests for three patterns gks"
expectfn "$clixon_cli -1f $cfg -l o set c threematch gks" 0 '^$'

new "CLI tests for three patterns abcg (should fail)"
expectfn "$clixon_cli -1f $cfg -l o set c threematch abcg" 255 '^CLI syntax error:'


if [ $BE -ne 0 ]; then
    new "Kill backend"
    # Check if premature kill
    pid=$(pgrep -u root -f clixon_backend)
    if [ -z "$pid" ]; then
	err "backend already dead"
    fi
    # kill backend
    stop_backend -f $cfg
    sudo pkill -u root -f clixon_backend
fi

rm -rf $dir

# unset conditional parameters 
unset regex
