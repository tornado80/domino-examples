; Both games are stateless. The CPA games' keys become the inactive inner and
; outer keys; the inner encryptions of column (not bo) are fed to the outer CPA
; game, which discards them, so their randomness is unmapped.
(define-fun randomness-mapping-GetView
    (
        (sample-id-left SampleId)
        (sample-id-right SampleId)
        (sample-ctr-left Int)
        (sample-ctr-right Int)
    )
    Bool
    (let ((bo (el2-2 (el2-2 <arg-Receiver1out4Security_Hybrid1-GetView-inputs>))))
    (or
        (and (= sample-ctr-left 0)
             (= sample-ctr-right 0)
             (or
                 ; keys: the CPA games' keys become the inactive inner and outer keys
                 (and (= sample-id-left  (sample-id "ReceiverReduction" "GetView" "kia"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "kia")))
                 (and (= sample-id-left  (sample-id "ReceiverReduction" "GetView" "koa"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "koa")))
                 (and (= sample-id-left  (sample-id "CPA_inner" "Enc" "k"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "kix")))
                 (and (= sample-id-left  (sample-id "CPA_outer" "Enc" "k"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "kox")))
                 ; inner randomness of column bo; that of column (not bo) is discarded by the outer CPA game
                 (and (= sample-id-left  (ite bo (sample-id "ReceiverReduction" "GetView" "ria1") (sample-id "ReceiverReduction" "GetView" "ria0")))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ri1")))
                 (and (= sample-id-left  (ite bo (sample-id "CPA_inner" "Enc" "r1") (sample-id "CPA_inner" "Enc" "r0")))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ri2")))
                 ; outer randomness
                 (and (= sample-id-left  (sample-id "ReceiverReduction" "GetView" "ro1"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ro1")))
                 (and (= sample-id-left  (sample-id "ReceiverReduction" "GetView" "ro2"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ro2")))
                 (and (= sample-id-left  (sample-id "CPA_outer" "Enc" "r0"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ro3")))
                 (and (= sample-id-left  (sample-id "CPA_outer" "Enc" "r1"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ro4")))))
        ; the 1-out-of-2 simulator's randomness, once per 1-out-of-2 instance
        (and (= sample-ctr-left sample-ctr-right)
             (= sample-id-left  (sample-id "ReceiverSim1out2" "GetSimView" "rsim"))
             (= sample-id-right (sample-id "ReceiverSim1out2" "GetSimView" "rsim")))))
)

(define-state-relation invariant (left right)
    true
)
