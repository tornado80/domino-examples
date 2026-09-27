; Ideal PRF on a fresh nonce vs. Coll (no abort) + lazily sampled pad table:
; the nonce is the same draw, and the random-function table is the pad table.
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
            (and (= sample-id-left  (sample-id "Reduction1" "ENC" "r"))
                 (= sample-id-right (sample-id "Coll" "GET" "x")))
            (and (= sample-id-left  (sample-id "Prf" "EVAL" "r"))
                 (= sample-id-right (sample-id "Reduction2" "ENC" "pad")))))
)

(define-state-relation invariant (left right)
    (= left.Prf.T right.Reduction2.T)
)
