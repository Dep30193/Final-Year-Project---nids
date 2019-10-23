def pass_main(pattern, text):
    P = list(pattern)
    T = list(text)
    x = 0
    n_match = 0
    shift = 0
    len_text = len(T)
    t = len_text - 1
    len_patt = len(P)
    p = len_patt - 1
    nx = 0
    # -----------------------------------------------------------------#
    def indexOutbound_test(t):
        global nx
        if (t > len(T) - 1):
            nx = 1
            return False
        else:
            return True

    # ---------------------------each data-----------------------------------------------#
    if len_text < len_patt:
        nx = 1
    if shift == 0:  # first iterate trigger only
        shift += 1
        t = p
    ##------iterate----------------------------------------------##
    while True:
        if nx != 0:
            break
        else:
            pass

        if len(T) < len(P):
            break
        ####################################
        while P[p] == T[t]:
            if nx != 0:
                break
            n_match += 1

            if n_match < len_patt:  # n_match refer to character_matched_number
                shift = shift + 1
                t = t-1
                p = p-1
                continue
            elif n_match == len_patt:
                x += 1              # x refer to each matched_string
                t += shift  # shift right
                p = len(P) - 1
                n_match = 0
                shift = 1
                if indexOutbound_test(t):
                    continue
                else:
                    break
            else:
                print('perror')
        ####################################
        if n_match == 0:
            shift = 1
        t += shift  # shift right
        p = len(P) - 1
        n_match = 0
        if indexOutbound_test(t):
            continue
        else:
            break
    return x




