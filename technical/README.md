# Technical Documents

A non-comprehensive assortment of technical explanations and visualizations. More accessible readings may be uploaded here or elsewhere in the future (but don't count on them).

## Flowchart
```mermaid
flowchart TD
    style one stroke:#68A691,stroke-width:2px
    style two stroke:#D67AB1,stroke-width:2px

    op_path -->|deref in L1| var_1

    var_1 -->|step 3| next_var_ptr1
    var_1 -->|step 4| expr_1
    var_1 -->|step 2| var_ident_ptr1
    var_1 -->|step 1| check_dfa_start_ptr1

    var_ident_ptr1 -->|deref in L2| var_ident1

    next_var_ptr1 -->|if HAS_NEXT flag is set, deref in L1| var_2
    var_2 -->|keep iterating| etc_1
    
    expr_1 --> vuln_text_ptr1
    expr_1 --> aes_gcm_tag_ptr1
    expr_1 --> next_test_ident_ptr1
    expr_1 --> expr_dfa_start_ptr1

    aes_gcm_tag_ptr1 -->|deref in L1| aes_gcm_tag
    aes_gcm_tag --> AES_GCM
    next_test_ident_ptr1 -->|deref in L2| next_test_ident1
    expr_dfa_start_ptr1 -->|deref in L2| expr_dfa_start1
    expr_dfa_start1 -->|use as starting state in L2| expr_dfa
    var_ident1 --> set_internal_ident_val

    next_test_ident1 -->|if HAS_NEXT flag is set, deref in L2| next_test_ident2
    next_test_ident2 -->|keep iterating| etc_2

    next_test_ident1 -->|get internal value| ident_val

    expr_dfa -->|done|expr_halting_state
    ident_val --> expr_dfa

    vuln_text_ptr1 -->|deref in L1| ciphertext
    ciphertext --> AES_GCM
   expr_halting_state -->|use SHA256 hash as key| AES_GCM

    AES_GCM -->|if successful| output
    output --> done
    AES_GCM -->|else| done

    op_path -->|query bytes| file
    file -->|iterate over bytes| byte
    byte --> check_dfa
    check_dfa_start_ptr1 -->|deref in L3| check_dfa_start1
    check_dfa_start1 -->|use as starting state in L3| check_dfa
    check_dfa -->|done| check_halting_state

    check_halting_state --> set_internal_ident_val

    etc_1[...]
    etc_2[...]

    subgraph one [ ]
    next_var_ptr1
    expr_1
    var_ident_ptr1
    check_dfa_start_ptr1
    end

    subgraph two [ ]
    vuln_text_ptr1
    aes_gcm_tag_ptr1
    expr_dfa_start_ptr1
    next_test_ident_ptr1
    end
```
