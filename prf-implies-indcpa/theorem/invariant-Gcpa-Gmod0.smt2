; The CPA key and the PRF key are the same lazily sampled value; the
; encryption nonce r is the same draw on both sides.
(define-fun randomness-mapping-ENC
    (
        (sample-id-left SampleId)
        (sample-id-right SampleId)
        (sample-ctr-left Int)
        (sample-ctr-right Int)
    )
    Bool
    (and
        (= sample-ctr-left 0)
        (= sample-ctr-right 0)
        (or
            (and (= sample-id-left  (sample-id "CPA" "ENC" "k"))
                 (= sample-id-right (sample-id "Prf" "EVAL" "k")))
            (and (= sample-id-left  (sample-id "Construction" "Enc" "r"))
                 (= sample-id-right (sample-id "Reduction1" "ENC" "r")))))
)

(define-state-relation invariant (left right)
    (= left.CPA.k right.Prf.k)
)
