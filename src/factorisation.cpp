#include <stdlib.h>
#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

using namespace libsnark;
using namespace std;

int main() {
    typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

    // Initialize the curve parameters

    default_r1cs_ppzksnark_pp::init_public_params();

    // Create protoboard

    protoboard<FieldT> pb;

    // Define variables

    pb_variable<FieldT> x;
    pb_variable<FieldT> y;
    pb_variable<FieldT> out;

    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes

    out.allocate(pb, "out");
    x.allocate(pb, "x");
    y.allocate(pb, "y");

    // This sets up the protoboard variables
    // so that the first one (out) represents the public
    // input and the rest is private input
    pb.set_input_sizes(1);

    // Add R1CS constraints to protoboard

    // x*y = out
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, y, out));

    // Trusted setup
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(
            constraint_system);

    // Add witness values
    pb.val(x) = 3;
    pb.val(y) = 9;
    pb.val(out) = 27;

    // Create proof
    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(
            keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Verify proof
    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    cout << "FOR SUCCESSFUL VERIFICATION" << endl;
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;

    // Add witness values
    pb.val(x) = 3;
    pb.val(y) = 10;
    pb.val(out) = 27;

    // Create proof
    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof1 = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(
            keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Verify proof
    bool verified1 = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof1);

    cout << "FOR UNSUCCESSFUL VERIFICATION" << endl;
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified1 << endl;

    return 0;
}