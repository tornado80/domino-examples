; Ideal PRF on a fresh nonce vs. Nonce (no abort) + lazily sampled pad table:
; the nonce is the same draw, and the random-function table is the pad table.
(define-fun randomness-mapping-Enc
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
            (and (= sample-id-left  (sample-id "Reduction1" "Enc" "nonce"))
                 (= sample-id-right (sample-id "Nonce" "Sample" "nonce")))
            (and (= sample-id-left  (sample-id "Prf" "Eval" "r"))
                 (= sample-id-right (sample-id "Reduction2" "Enc" "pad")))))
)

(define-state-relation invariant (left right)
    (= left.Prf.T right.Reduction2.T)
)
