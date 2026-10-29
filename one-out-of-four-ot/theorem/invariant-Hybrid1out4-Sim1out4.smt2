; Both games are stateless: they sample the four keys and the encryption
; randomness once per call, and run the 1-out-of-2 simulator twice.
(define-fun randomness-mapping-GetView
    (
        (sample-id-left SampleId)
        (sample-id-right SampleId)
        (sample-ctr-left Int)
        (sample-ctr-right Int)
    )
    Bool
    (or
        (and (= sample-ctr-left 0)
             (= sample-ctr-right 0)
             (or
                 (and (= sample-id-left  (sample-id "view4" "GetView" "k00"))
                      (= sample-id-right (sample-id "sim4" "GetSimView" "k00")))
                 (and (= sample-id-left  (sample-id "view4" "GetView" "k01"))
                      (= sample-id-right (sample-id "sim4" "GetSimView" "k01")))
                 (and (= sample-id-left  (sample-id "view4" "GetView" "k10"))
                      (= sample-id-right (sample-id "sim4" "GetSimView" "k10")))
                 (and (= sample-id-left  (sample-id "view4" "GetView" "k11"))
                      (= sample-id-right (sample-id "sim4" "GetSimView" "k11")))
                 (and (= sample-id-left  (sample-id "view4" "GetView" "renc"))
                      (= sample-id-right (sample-id "sim4" "GetSimView" "renc")))))
        ; the simulator's randomness, once per 1-out-of-2 instance
        (and (= sample-ctr-left sample-ctr-right)
             (= sample-id-left  (sample-id "sim2" "GetSimView" "rsim"))
             (= sample-id-right (sample-id "sim2" "GetSimView" "rsim"))))
)

(define-state-relation invariant (left right)
    true
)
