#include <stdlib.h>
#include <iostream>
#include <chrono>

#include "longsightf-gadget.hpp"

#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"

using namespace std;
using namespace std::chrono;

typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

bool mimc1() {
    protoboard<FieldT> pb;
    pb_variable<FieldT> xL;
    pb_variable<FieldT> xR;

    xL.allocate(pb, "xL");
    xR.allocate(pb, "xR");

    LongsightF5p5_gadget<FieldT> g(pb, xL, xR, "mimcf5p5");

    g.generate_r1cs_constraints();

    // Trusted setup
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(
            constraint_system);

    auto expected_L = FieldT("21871881226116355513319084168586976250335411806112527735069209751513595455673");
    auto expected_R = FieldT("55049861378429053168722197095693172831329974911537953231866155060049976290");
    auto expected_output = FieldT("13760655609088709433007830795510519756645189711992567034072335606485861811900");

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

        if( expected_output != pb.val(g.result()) ) {
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

    cout << "Number of constraints: " << pb.num_constraints() << endl;
    cout << "Total iterations : " << iterations << endl;
    cout << "Total constraint generation time (seconds): " << tc.count() << endl;
    cout << "Total proving time (seconds): " << tp.count() << endl;
    cout << "Total verification time (seconds): " << tv.count() << endl;

    return true;
}

void generate_mimc_roundconst_gfp(std::vector<FieldT> &round_consts,
                                  int num_rounds)
{
    for(int i = 0;i < num_rounds;i++) {
        round_consts.emplace_back(FieldT::random_element());
    }
}

template <template <typename> class G>
bool mimc_fiestel(protoboard<FieldT> &pb,
                  const pb_variable<FieldT> &in_xL,
                  const pb_variable<FieldT> &in_xR,
                  int num_rounds, int num_iterations,
                  FieldT expected_L, FieldT expected_R) {

    std::vector<FieldT> round_consts;
    generate_mimc_roundconst_gfp(round_consts, num_rounds);
    auto g = G<FieldT>(pb, round_consts, in_xL, in_xR, "some", true);
    g.generate_r1cs_constraints();

    // Trusted setup
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(
            constraint_system);

    int i = 0;

    duration<double> tc(0);
    duration<double> tp(0);
    duration<double> tv(0);

    while (i < num_iterations) {
        steady_clock::time_point begin = steady_clock::now();

        pb.val(in_xL) = expected_L;
        pb.val(in_xR) = expected_R;

        g.generate_r1cs_witness();

        steady_clock::time_point mid = steady_clock::now();
        tc += duration_cast<duration<double>>(mid - begin);

        cout << "Satisfied status: " << pb.is_satisfied() << endl;

        /*if( expected_output != pb.val(g.result()) ) {
            cerr << "Unexpected result!"  << endl;
            return false;
        }*/


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

    cout << "Number of rounds: " << num_rounds << endl;
    cout << "Number of constraints: " << pb.num_constraints() << endl;
    cout << "Total iterations : " << num_iterations << endl;
    cout << "Total constraint generation time (seconds): " << tc.count() << endl;
    cout << "Total proving time (seconds): " << tp.count() << endl;
    cout << "Total verification time (seconds): " << tv.count() << endl;

    return true;
}

int main() {
    default_r1cs_ppzksnark_pp::init_public_params();

//    cout << "Field capacity" << FieldT::capacity() << endl;

    /*if (! mimc1()) {
        return -1;
    }
    */

    protoboard<FieldT> pb;
    pb_variable<FieldT> xL;
    pb_variable<FieldT> xR;

    xL.allocate(pb, "xL");
    xR.allocate(pb, "xR");

    auto expected_L = FieldT("21871881226116355513319084168586976250335411806112527735069209751513595455673");
    auto expected_R = FieldT("55049861378429053168722197095693172831329974911537953231866155060049976290");

    if (!mimc_fiestel<LongsightF_gadget>(pb, xL, xR, 322, 1, expected_L, expected_R)) {
        return -1;
    }
    if (!mimc_fiestel<LongsightFInv_gadget>(pb, xL, xR, 322, 1, expected_L, expected_R)) {
        return -1;
    }
    return 0;
}