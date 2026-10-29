; Both games are stateless. The keys and the randomness of row bi of the
; inner encryptions move to ReceiverReductionInner, those of row (not bi) to
; the CPA game, so the mapping depends on the receiver's input bi.
(define-fun randomness-mapping-GetView
    (
        (sample-id-left SampleId)
        (sample-id-right SampleId)
        (sample-ctr-left Int)
        (sample-ctr-right Int)
    )
    Bool
    (let ((bi (el2-1 (el2-2 <arg-Receiver1out4Security_Hybrid0-GetView-inputs>))))
    (or
        (and (= sample-ctr-left 0)
             (= sample-ctr-right 0)
             (or
                 ; inner keys: ki_bi is the active key, ki_(not bi) the CPA key
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ki1") (sample-id "ReceiverView1out4" "GetView" "ki0")))
                      (= sample-id-right (sample-id "ReceiverReductionInner" "GetView" "kia")))
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ki0") (sample-id "ReceiverView1out4" "GetView" "ki1")))
                      (= sample-id-right (sample-id "CPA" "Enc" "k")))
                 ; inner randomness: row bi in the reduction, row (not bi) in the CPA game
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ri3") (sample-id "ReceiverView1out4" "GetView" "ri1")))
                      (= sample-id-right (sample-id "ReceiverReductionInner" "GetView" "ria0")))
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ri4") (sample-id "ReceiverView1out4" "GetView" "ri2")))
                      (= sample-id-right (sample-id "ReceiverReductionInner" "GetView" "ria1")))
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ri1") (sample-id "ReceiverView1out4" "GetView" "ri3")))
                      (= sample-id-right (sample-id "CPA" "Enc" "r0")))
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ri2") (sample-id "ReceiverView1out4" "GetView" "ri4")))
                      (= sample-id-right (sample-id "CPA" "Enc" "r1")))
                 ; outer keys and randomness are unchanged
                 (and (= sample-id-left  (sample-id "ReceiverView1out4" "GetView" "ko0"))
                      (= sample-id-right (sample-id "ReceiverReductionInner" "GetView" "ko0")))
                 (and (= sample-id-left  (sample-id "ReceiverView1out4" "GetView" "ko1"))
                      (= sample-id-right (sample-id "ReceiverReductionInner" "GetView" "ko1")))
                 (and (= sample-id-left  (sample-id "ReceiverView1out4" "GetView" "ro1"))
                      (= sample-id-right (sample-id "ReceiverReductionInner" "GetView" "ro1")))
                 (and (= sample-id-left  (sample-id "ReceiverView1out4" "GetView" "ro2"))
                      (= sample-id-right (sample-id "ReceiverReductionInner" "GetView" "ro2")))
                 (and (= sample-id-left  (sample-id "ReceiverView1out4" "GetView" "ro3"))
                      (= sample-id-right (sample-id "ReceiverReductionInner" "GetView" "ro3")))
                 (and (= sample-id-left  (sample-id "ReceiverView1out4" "GetView" "ro4"))
                      (= sample-id-right (sample-id "ReceiverReductionInner" "GetView" "ro4")))))
        ; the 1-out-of-2 simulator's randomness, once per 1-out-of-2 instance
        (and (= sample-ctr-left sample-ctr-right)
             (= sample-id-left  (sample-id "ReceiverSim1out2" "GetSimView" "rsim"))
             (= sample-id-right (sample-id "ReceiverSim1out2" "GetSimView" "rsim")))))
)

(define-state-relation invariant (left right)
    true
)
