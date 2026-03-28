; SPDX-License-Identifier: PMPL-1.0-or-later
;; guix.scm — GNU Guix package definition for panic-attacker
;; Usage: guix shell -f guix.scm

(use-modules (guix packages)
             (guix build-system gnu)
             (guix licenses))

(package
  (name "panic-attacker")
  (version "0.1.0")
  (source #f)
  (build-system gnu-build-system)
  (synopsis "panic-attacker")
  (description "panic-attacker — part of the hyperpolymath ecosystem.")
  (home-page "https://github.com/hyperpolymath/panic-attacker")
  (license ((@@ (guix licenses) license) "PMPL-1.0-or-later"
             "https://github.com/hyperpolymath/palimpsest-license")))
