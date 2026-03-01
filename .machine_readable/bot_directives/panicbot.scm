;; SPDX-License-Identifier: PMPL-1.0-or-later
;; Panicbot directives for panic-attacker self-scanning
;;
;; This file tells panicbot (gitbot-fleet verifier) how to scan this repo.
;; Dynamic attack modes are denied because panic-attack is a CLI tool, not
;; a long-running service — executing it under stress would test cargo/rustc
;; internals, not our code.

(bot-directive
  (bot "panicbot")
  (scope "static-analysis")
  (allow ("assail" "adjudicate" "diagnostics"))
  (deny ("attack" "assault" "ambush" "amuck" "abduct" "axial"))
  (config
    (min-severity "low")
    (timeout-seconds 300)))
