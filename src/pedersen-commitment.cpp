#include <stdlib.h>
#include <iostream>
#include <chrono>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"

#include "libff/algebra/curves/bn128/bn128_pp.hpp"
#include "libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp"
#include "pedersen-commitment.hpp"

using namespace libsnark;
using namespace std;
using namespace std::chrono;

typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
typedef libff::G1<default_r1cs_ppzksnark_pp> G1;
//typedef libsnark::G1_variable<default_r1cs_ppzksnark_pp> G1_var;


int main() {
    default_r1cs_ppzksnark_pp::init_public_params();

    protoboard<FieldT> pb;

    G1 P_val = FieldT::random_element() * G1::one();
    G1 Q_val = FieldT::random_element() * G1::one();
//    auto z = new G1_variable<default_r1cs_ppzksnark_pp>(pb, "P");
//    G1_var P(pb, "P");
//    G1_variable<default_r1cs_ppzksnark_pp> Q(pb, "Q");



    return 0;
}