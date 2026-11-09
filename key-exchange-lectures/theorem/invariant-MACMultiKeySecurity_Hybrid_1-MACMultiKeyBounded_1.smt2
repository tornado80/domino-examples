;; Top endpoint: h(n_ideal, true) == the bounded multi-key game with ideal Verify.
;; The cap keeps every key at position n_real + kid <= n_ideal = i, so every key
;; is ideal: key q = n_ideal - n_real in the single-key game, the others locally.

(define-state-relation next-is-q (l r)
    (= (+ l.MACHybridReduction.n_real l.MACHybridReduction.kid_ctr 1)
       l.MACHybridReduction.i))

(define-fun randomness-mapping-MAC_Gen
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-right (sample-id "MACMultiKey" "MAC_Gen" "psk"))
         (ite (next-is-q <<game-state-MACMultiKeySecurity_Hybrid_1-old>> <<game-state-MACMultiKeyBounded_1-old>>)
              (= sample-id-left (sample-id "MACSingleKey" "Single_Gen" "psk"))
              (= sample-id-left (sample-id "MACHybridReduction" "MAC_Gen" "psk")))))

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
         (= l.MACHybridReduction.kid_ctr r.MACMultiKey.kid_ctr)
         (= l.MACHybridReduction.kid_ctr l.KeyBound.count)
         (= l.MACHybridReduction.i l.KeyBound.n_ideal)
         (= l.MACHybridReduction.n_real l.KeyBound.n_real)
         (>= l.MACHybridReduction.kid_ctr 0)))

(define-state-relation cap (l r)
    (or (= l.KeyBound.count 0)
        (<= (+ l.KeyBound.n_real l.KeyBound.count) l.KeyBound.n_ideal)))

(define-state-relation fresh-keys (l r)
    (forall ((kid Int))
        (=> (or (> kid l.MACHybridReduction.kid_ctr) (<= kid 0))
            (and ((_ is mk-none) (select l.MACHybridReduction.K kid))
                 ((_ is mk-none) (select r.MACMultiKey.K kid))))))

(define-state-relation other-keys (l r)
    (forall ((kid Int))
        (=> (not (= (+ l.MACHybridReduction.n_real kid) l.MACHybridReduction.i))
            (and (= (select l.MACHybridReduction.K kid) (select r.MACMultiKey.K kid))
                 (= (select l.MACHybridReduction.C kid) (select r.MACMultiKey.C kid))))))

(define-state-relation other-tags (l r)
    (forall ((kid Int) (m (Tuple3 Bits_lpk Bits_lct (Maybe Bits_ltag))))
        (=> (not (= (+ l.MACHybridReduction.n_real kid) l.MACHybridReduction.i))
            (= (select l.MACHybridReduction.T (mk-tuple2 kid m))
               (select r.MACMultiKey.T (mk-tuple2 kid m))))))

(define-state-relation key-q (l r)
    (let ((q (- l.MACHybridReduction.i l.MACHybridReduction.n_real)))
        (and (= l.MACSingleKey.k (select r.MACMultiKey.K q))
             (= l.MACSingleKey.C (select r.MACMultiKey.C q)))))

(define-state-relation tags-q (l r)
    (let ((q (- l.MACHybridReduction.i l.MACHybridReduction.n_real)))
        (forall ((m (Tuple3 Bits_lpk Bits_lct (Maybe Bits_ltag))))
            (= (select l.MACSingleKey.T m)
               (select r.MACMultiKey.T (mk-tuple2 q m))))))

(define-state-relation invariant (l r)
    (and (counters l r)
         (cap l r)
         (fresh-keys l r)
         (other-keys l r)
         (other-tags l r)
         (key-q l r)
         (tags-q l r)))
