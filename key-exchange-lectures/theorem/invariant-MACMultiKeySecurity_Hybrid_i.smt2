;; Hybrid step: h(i, true) == h(i+1, false). Writing d for the key at position i
;; and e = d + 1 for the key at position i + 1:
;;   key d is in the ideal single-key game on the left and locally ideal on the right;
;;   key e is locally real on the left and in the real single-key game on the right;
;;   every other key is handled the same on both sides.

(define-state-relation next-is-d (l r)
    (= (+ l.MACHybridReduction.n_real l.MACHybridReduction.kid_ctr 1)
       l.MACHybridReduction.i))

(define-state-relation next-is-e (l r)
    (= (+ l.MACHybridReduction.n_real l.MACHybridReduction.kid_ctr 1)
       r.MACHybridReduction.i))

(define-fun randomness-mapping-MAC_Gen
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (ite (next-is-d <<game-state-MACMultiKeySecurity_Hybrid_i$true$-old>> <<game-state-MACMultiKeySecurity_Hybrid_i$false$+-old>>)
              (and (= sample-id-left (sample-id "MACSingleKey" "Single_Gen" "psk"))
                   (= sample-id-right (sample-id "MACHybridReduction" "MAC_Gen" "psk")))
              (ite (next-is-e <<game-state-MACMultiKeySecurity_Hybrid_i$true$-old>> <<game-state-MACMultiKeySecurity_Hybrid_i$false$+-old>>)
                   (and (= sample-id-left (sample-id "MACHybridReduction" "MAC_Gen" "psk"))
                        (= sample-id-right (sample-id "MACSingleKey" "Single_Gen" "psk")))
                   (and (= sample-id-left (sample-id "MACHybridReduction" "MAC_Gen" "psk"))
                        (= sample-id-right (sample-id "MACHybridReduction" "MAC_Gen" "psk")))))))

(define-fun randomness-mapping-MAC_Corrupt
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-MAC_Mac
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-MAC_Verify
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-state-relation counters (l r)
    (and (= l.KeyBound.count r.KeyBound.count)
         (= l.MACHybridReduction.kid_ctr r.MACHybridReduction.kid_ctr)
         (= r.MACHybridReduction.i (+ 1 l.MACHybridReduction.i))
         (= l.MACHybridReduction.n_real r.MACHybridReduction.n_real)))

(define-state-relation fresh-keys (l r)
    (forall ((kid Int))
        (=> (> kid l.MACHybridReduction.kid_ctr)
            (and ((_ is mk-none) (select l.MACHybridReduction.K kid))
                 ((_ is mk-none) (select r.MACHybridReduction.K kid))))))

(define-state-relation other-keys (l r)
    (forall ((kid Int))
        (=> (and (not (= (+ l.MACHybridReduction.n_real kid) l.MACHybridReduction.i))
                 (not (= (+ l.MACHybridReduction.n_real kid) r.MACHybridReduction.i)))
            (and (= (select l.MACHybridReduction.K kid) (select r.MACHybridReduction.K kid))
                 (= (select l.MACHybridReduction.C kid) (select r.MACHybridReduction.C kid))))))

(define-state-relation other-tags (l r)
    (forall ((kid Int) (m (Tuple3 Bits_lpk Bits_lct (Maybe Bits_ltag))))
        (=> (and (not (= (+ l.MACHybridReduction.n_real kid) l.MACHybridReduction.i))
                 (not (= (+ l.MACHybridReduction.n_real kid) r.MACHybridReduction.i)))
            (= (select l.MACHybridReduction.T (mk-tuple2 kid m))
               (select r.MACHybridReduction.T (mk-tuple2 kid m))))))

(define-state-relation key-d (l r)
    (let ((d (- l.MACHybridReduction.i l.MACHybridReduction.n_real)))
        (and (= l.MACSingleKey.k (select r.MACHybridReduction.K d))
             (= l.MACSingleKey.C (select r.MACHybridReduction.C d)))))

(define-state-relation tags-d (l r)
    (let ((d (- l.MACHybridReduction.i l.MACHybridReduction.n_real)))
        (forall ((m (Tuple3 Bits_lpk Bits_lct (Maybe Bits_ltag))))
            (= (select l.MACSingleKey.T m)
               (select r.MACHybridReduction.T (mk-tuple2 d m))))))

(define-state-relation key-e (l r)
    (let ((e (- r.MACHybridReduction.i l.MACHybridReduction.n_real)))
        (= r.MACSingleKey.k (select l.MACHybridReduction.K e))))

(define-state-relation invariant (l r)
    (and (counters l r)
         (fresh-keys l r)
         (other-keys l r)
         (other-tags l r)
         (key-d l r)
         (tags-d l r)
         (key-e l r)))
