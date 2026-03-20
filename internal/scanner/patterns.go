package scanner

import (
	"fmt"
	"regexp"
)

// CompromisedActions maps a GitHub Action (owner/action-name) to the list of
// compromised commit SHAs known to be associated with that action.
// These are the actions and SHAs confirmed to be part of the aquasecurity/trivy
// supply chain compromise on 2026-03-19 to 2026-03-20.
var CompromisedActions = map[string][]string{
	"aquasecurity/trivy-action": {
		"f77738448eec70113cf711656914b61905b3bd47",
		"b9faa60f85f6f780a34b8d0faaf45b3e3966fdda",
		"3c615ac0f29e743eda8863377f9776619fd2db76",
		"c19401b2f58dc6d2632cb473d44be98dd8292a93",
		"4209dcadeaea6a7df69262fef1beeda940881d4d",
		"61fbe20b7589e6b61eedcd5fe1e958e1a95fbd13",
		"0d49ceb356f7d4735c63bd0d5c7e67665ec7f80c",
		"2e7964d59cd24d1fd2aa4d6a5f93b7f09ea96947",
		"1d74e4cf63b7cf083cf92bf5923cf037f7011c6b",
		"3201ddddd69a1419c6f1511a14c5945ba3217126",
		"ea56cd31d82b853932d50f1144e95b21817e52cf",
		"f5c9fd927027beaa3760d2a84daa8b00e6e5ee21",
		"9738180dd24427b8824445dbbc23c30ffc1cb0d8",
		"ef3a510e3f94df3ea9fcd01621155ca5f2c3bf5b",
		"bb75a9059c2d5803db49e6ed6c6f7e0b367f96be",
		"22e864e71155122e2834eb0c10d0e7e0b8f65aa3",
		"6ec7aaf336b7d2593d980908be9bc4fed6d407c6",
		"555e7ad4c895c558c7214496df1cd56d1390c516",
		"794b6d99daefd5e27ecb33e12691c4026739bf98",
		"506d7ff06abc509692c600b5b69b4dc6ceaa4b15",
		"91d5e0a13afab54533a95f8019dd7530bd38a071", // 0.0.8
		"252554b0e1130467f4301ba65c55a9c373508e35", // 0.0.9
		"9e8968cb83234f0de0217aa8c934a68a317ee518", // 0.1.0
		"8aa8af3ea1de8e968a3e49a40afb063692ab8eae", // 0.10.0
		"e53b0483d08da44da9dfe8a84bf2837e5163699b", // 0.11.0
		"276ca9680f6df9016db12f7c48571e5c4639451d", // 0.11.1
		"8ae5a08aec3013ee8f6132b2a9012b45002f8eaa", // 0.11.2
		"820428afeb64484d311211658383ce7f79d31a0a", // 0.12.0
		"cf19d27c8a7fb7a8bbf1e1000e9318749bcd82cf", // 0.13.0
		"405e91f329294fb696f55793203abf1f6aba9b40", // 0.13.1
		"2297a1b967ecc05ba2285eb6af56ab4da554ecae", // 0.14.0
		"2b1dac84ff12ba56158b3a97e2941a587cb20da9", // 0.15.0
		"f4f1785be270ae13f36f6a8cfbf6faaae50e660a", // 0.16.0
		"3d1b5be1589a83fc98b82781c263708b2eb3b47b", // 0.16.1
		"985447b035c447c1ed45f38fad7ca7a4254cb668", // 0.17.0
		"85cb72f1e8ee5e6e44488cd6cbdbca94722f96ed", // 0.18.0
		"38623bf26706d51c45647909dcfb669825442804", // 0.19.0
		"7f6f0ce52a59bdfc5757c3982aac2353b58f4c73", // 0.2.0
		"0891663bc55073747be0eb864fbec3727840945d", // 0.2.1
		"3dffed04dc90cf1c548f40577d642c52241ec76c", // 0.2.2
		"cf1692a1fc7a47120e6508309765db7e33477946", // 0.2.3
		"848d665ed24dc1a41f6b4b7c7ffac7693d6b37be", // 0.2.4
		"fa4209b6182a4c1609ce34d40b67f5cfd7f00f53", // 0.2.5
		"9092287c0339a8102f91c5a257a7e27625d9d029", // 0.20.0
		"b7befdc106c600585d3eec87d7e98e1c136839ae", // 0.21.0
		"9ba3c3cd3b23d033cd91253a9e61a4bf59c8a670", // 0.22.0
		"fd090040b5f584f4fcbe466878cb204d0735dcf4", // 0.23.0
		"e0198fd2b6e1679e36d32933941182d9afa82f6f", // 0.24.0
		"ddb94181dcbc723d96ffc07fddd14d97e4849016", // 0.25.0
		"b7252377a3d82c73d497bfafa3eabe84de1d02c4", // 0.26.0
		"66c90331c8b991e7895d37796ac712b5895dda3b", // 0.27.0
		"c5967f85626795f647d4bf6eb67227f9b79e02f5", // 0.28.0
		"9c000ba9d482773cbbc2c3544d61b109bc9eb832", // 0.29.0
		"8cfb9c31cc944da57458555aa398bb99336d5a1f", // 0.3.0
		"ad623e14ebdfe82b9627811d57b9a39e283d6128", // 0.30.0
		"8519037888b189f13047371758f7aed2283c6b58", // 0.31.0
		"fd429cf86db999572f3d9ca7c54561fdf7d388a4", // 0.32.0
		"19851bef764b57ff95b35e66589f31949eeb229d", // 0.33.0
		"91e7c2c36dcad14149d8e455b960af62a2ffb275", // 0.33.1
		"ab6606b76e5a054be08cab3d07da323e90e751e8", // 0.34.0
		"a9bc513ea7989e3234b395cafb8ed5ccc3755636", // 0.34.1
		"ddb9da4475c1cef7d5389062bdfdfbdbd1394648", // 0.34.2
		"18f01febc4c3cd70ce6b94b70e69ab866fc033f5", // 0.4.0
		"7b955a5ece1e1b085c12dac7ac10e0eb1f5b0d4d", // 0.4.1
		"d488f4388ff4aa268906e25c2144f1433a4edec2", // 0.5.0
		"fa78e67c0df002c509bcdea88677fb5e2fe6a9b1", // 0.5.1
		"a5b4818debf2adbaba872aaffd6a0f64a26449fa", // 0.6.0
		"6fc874a1f9d65052d4c67a314da1dae914f1daff", // 0.6.1
		"2a51c5c5bb1fd1f0e134c9754f1702cfa359c3dd", // 0.6.2
		"ddb6697447a97198bdef9bae00215059eb5e8bc2", // 0.7.0
		"aa3c46a9643b18125abb8aefc13219014e9c4be8", // 0.7.1
		"4bdcc5d9ef3ddb42ccc9126e6c07faa3df2807e3", // 0.8.0
		"b745a35bad072d93a9b83080e9920ec52c6b5a27", // 0.9.0
		"da73ae0790e458e878b300b57ceb5f81ac573b46", // 0.9.1
		"7550f14b64c1c724035a075b36e71423719a1f30", // 0.9.2
	},
}

// ActionPattern is a compiled pattern for a single action + one of its SHAs.
type ActionPattern struct {
	Action string         // e.g. "aquasecurity/trivy-action"
	SHA    string         // the compromised commit SHA
	Regex  *regexp.Regexp // matches "action@sha" references in log text
}

// CompiledPatterns returns a slice of ActionPattern compiled once at startup.
// Panics on bad pattern (should never happen with static data).
func CompiledPatterns() []ActionPattern {
	var patterns []ActionPattern
	for action, shas := range CompromisedActions {
		for _, sha := range shas {
			// Match either:
			//   action@sha          — SHA-pinned reference in workflow YAML
			//   action@tag (SHA:sha) — tag-based ref; SHA appears in the
			//                          "Download action repository" log line
			escapedAction := regexp.QuoteMeta(action)
			escapedSHA := regexp.QuoteMeta(sha)
			pattern := fmt.Sprintf(`(?i)(?:%s@%s|%s[^\n]*\(SHA:%s\))`,
				escapedAction, escapedSHA,
				escapedAction, escapedSHA)
			re, err := regexp.Compile(pattern)
			if err != nil {
				panic(fmt.Sprintf("scanner: failed to compile pattern for %s@%s: %v", action, sha, err))
			}
			patterns = append(patterns, ActionPattern{
				Action: action,
				SHA:    sha,
				Regex:  re,
			})
		}
	}
	return patterns
}
