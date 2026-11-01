; Both games are stateless. The keys and the randomness of row bi of the inner
; encryptions and of column bo of the outer encryptions move to ReceiverReduction,
; those of row (not bi) to the inner CPA game and those of column (not bo) to the
; outer CPA game, so the mapping depends on the receiver's inputs bi and bo.
(define-fun randomness-mapping-GetView
    (
        (sample-id-left SampleId)
        (sample-id-right SampleId)
        (sample-ctr-left Int)
        (sample-ctr-right Int)
    )
    Bool
    (let ((bi (el2-1 (el2-2 <arg-Receiver1out4Security_Hybrid0-GetView-inputs>)))
          (bo (el2-2 (el2-2 <arg-Receiver1out4Security_Hybrid0-GetView-inputs>))))
    (or
        (and (= sample-ctr-left 0)
             (= sample-ctr-right 0)
             (or
                 ; inner keys: ki_bi is the active key, ki_(not bi) the key of the inner CPA game
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ki1") (sample-id "ReceiverView1out4" "GetView" "ki0")))
                      (= sample-id-right (sample-id "ReceiverReduction" "GetView" "kia")))
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ki0") (sample-id "ReceiverView1out4" "GetView" "ki1")))
                      (= sample-id-right (sample-id "CPA_inner" "Enc" "k")))
                 ; inner randomness: row bi in the reduction, row (not bi) in the inner CPA game
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ri3") (sample-id "ReceiverView1out4" "GetView" "ri1")))
                      (= sample-id-right (sample-id "ReceiverReduction" "GetView" "ria0")))
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ri4") (sample-id "ReceiverView1out4" "GetView" "ri2")))
                      (= sample-id-right (sample-id "ReceiverReduction" "GetView" "ria1")))
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ri1") (sample-id "ReceiverView1out4" "GetView" "ri3")))
                      (= sample-id-right (sample-id "CPA_inner" "Enc" "r0")))
                 (and (= sample-id-left  (ite bi (sample-id "ReceiverView1out4" "GetView" "ri2") (sample-id "ReceiverView1out4" "GetView" "ri4")))
                      (= sample-id-right (sample-id "CPA_inner" "Enc" "r1")))
                 ; outer keys: ko_bo is the active key, ko_(not bo) the key of the outer CPA game
                 (and (= sample-id-left  (ite bo (sample-id "ReceiverView1out4" "GetView" "ko1") (sample-id "ReceiverView1out4" "GetView" "ko0")))
                      (= sample-id-right (sample-id "ReceiverReduction" "GetView" "koa")))
                 (and (= sample-id-left  (ite bo (sample-id "ReceiverView1out4" "GetView" "ko0") (sample-id "ReceiverView1out4" "GetView" "ko1")))
                      (= sample-id-right (sample-id "CPA_outer" "Enc" "k")))
                 ; outer randomness: cells (bi, bo), (not bi, bo) in the reduction, column (not bo) in the outer CPA game
                 (and (= sample-id-left  (ite bi (ite bo (sample-id "ReceiverView1out4" "GetView" "ro4") (sample-id "ReceiverView1out4" "GetView" "ro3")) (ite bo (sample-id "ReceiverView1out4" "GetView" "ro2") (sample-id "ReceiverView1out4" "GetView" "ro1"))))
                      (= sample-id-right (sample-id "ReceiverReduction" "GetView" "ro1")))
                 (and (= sample-id-left  (ite (not bi) (ite bo (sample-id "ReceiverView1out4" "GetView" "ro4") (sample-id "ReceiverView1out4" "GetView" "ro3")) (ite bo (sample-id "ReceiverView1out4" "GetView" "ro2") (sample-id "ReceiverView1out4" "GetView" "ro1"))))
                      (= sample-id-right (sample-id "ReceiverReduction" "GetView" "ro2")))
                 (and (= sample-id-left  (ite bi (ite (not bo) (sample-id "ReceiverView1out4" "GetView" "ro4") (sample-id "ReceiverView1out4" "GetView" "ro3")) (ite (not bo) (sample-id "ReceiverView1out4" "GetView" "ro2") (sample-id "ReceiverView1out4" "GetView" "ro1"))))
                      (= sample-id-right (sample-id "CPA_outer" "Enc" "r0")))
                 (and (= sample-id-left  (ite (not bi) (ite (not bo) (sample-id "ReceiverView1out4" "GetView" "ro4") (sample-id "ReceiverView1out4" "GetView" "ro3")) (ite (not bo) (sample-id "ReceiverView1out4" "GetView" "ro2") (sample-id "ReceiverView1out4" "GetView" "ro1"))))
                      (= sample-id-right (sample-id "CPA_outer" "Enc" "r1")))))
        ; the 1-out-of-2 simulator's randomness, once per 1-out-of-2 instance
        (and (= sample-ctr-left sample-ctr-right)
             (= sample-id-left  (sample-id "ReceiverSim1out2" "GetSimView" "rsim"))
             (= sample-id-right (sample-id "ReceiverSim1out2" "GetSimView" "rsim")))))
)

(define-state-relation invariant (left right)
    true
)
