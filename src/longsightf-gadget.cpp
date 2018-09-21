#include <stdlib.h>
#include <iostream>
#include <chrono>

#include "longsightf-gadget.hpp"

using namespace std;
using namespace std::chrono;

typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

bool mimc1() {
    protoboard<FieldT> pb;
    pb_variable<FieldT> xL;
    pb_variable<FieldT> xR;

    xL.allocate(pb, "xL");
    xR.allocate(pb, "xR");

    LongsightF152p5_gadget<FieldT> g(pb, xL, xR, "mimcf152p5");

    g.generate_r1cs_constraints();

    printf("Number of constraints for sha256_two_to_one_hash_gadget: %zu\n", pb.num_constraints());

    // Trusted setup
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(
            constraint_system);

    auto expected_L = FieldT("21871881226116355513319084168586976250335411806112527735069209751513595455673");
    auto expected_R = FieldT("55049861378429053168722197095693172831329974911537953231866155060049976290");
    auto expected_ouptut = FieldT("11801552584949094581972187388927133931539817817986253233814495442311083852545");

    /*auto xL_bv = convert_field_element_to_bit_vector(expected_L);
    auto xR_bv = convert_field_element_to_bit_vector(expected_R);*/

    int i = 0;
    int iterations = 100;

    duration<double> tc(0);
    duration<double> tp(0);
    duration<double> tv(0);

    while (i < iterations) {
        steady_clock::time_point begin = steady_clock::now();

        pb.val(xL) = expected_L;
        pb.val(xR) = expected_R;

        g.generate_r1cs_witness();

        steady_clock::time_point mid = steady_clock::now();
        tc += duration_cast<duration<double>>(mid - begin);

        cout << "Satisfied status: " << pb.is_satisfied() << endl;

        if( expected_ouptut != pb.val(g.result()) ) {
            cerr << "Unexpected result!"  << endl;
            return false;
        }


        const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(
                keypair.pk, pb.primary_input(), pb.auxiliary_input());

        steady_clock::time_point end = steady_clock::now();
        tp += duration_cast<duration<double>>(end - begin);

        steady_clock::time_point begin1 = steady_clock::now();

        bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

        steady_clock::time_point end1 = steady_clock::now();
        tv += duration_cast<duration<double>>(end1 - begin1);

        if( verified != 1) {
            cerr << "Verification failed!"  << endl;
            return false;
        }
        i++;
    }

    cout << "Total iterations : " << iterations << endl;
    cout << "Total constraint generation time (seconds): " << tc.count() << endl;
    cout << "Total proving time (seconds): " << tp.count() << endl;
    cout << "Total verification time (seconds): " << tv.count() << endl;

    return true;
}

int main() {
    default_r1cs_ppzksnark_pp::init_public_params();

    if (! mimc1()) {
        return -1;
    }
    return 0;
}