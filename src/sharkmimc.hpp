#include <stdlib.h>
#include <iostream>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libff/algebra/fields/field_utils.hpp"

using namespace std;
using namespace libsnark;

template<typename FieldT>
class SharkMimc_gadget : public gadget<FieldT>
{
private:
    /*const static uint32_t key_size = 32;
    const u_char key[key_size] = {};*/
    const static uint32_t block_size = 256;
    const uint32_t gate_size = 32;
    const uint32_t branch_size = 32;
    static const uint32_t num_branches = 4;
    static const uint32_t middle_rounds = 38;
    static const uint32_t total_rounds = 3 + 38 + 3;
    static const uint32_t num_round_keys = (middle_rounds + 7) * num_branches;
    static const uint32_t num_round_constants = (middle_rounds + 6) * num_branches;
    const uint32_t branches_x_gate_size = num_branches * gate_size;
    const uint32_t branches_x_branch_size = num_branches * branch_size;
    const FieldT modulus;
    FieldT matrix_1[num_branches][num_branches];
    FieldT matrix_2[num_branches][num_branches];
public:
    FieldT round_constants[num_round_constants];
    FieldT round_keys[num_round_keys];
    const pb_variable_array<FieldT> input;

    pb_variable_array<FieldT> sbox_vals;
    pb_variable_array<FieldT> linear_vals;

    SharkMimc_gadget(FieldT modulus, protoboard<FieldT> &in_pb, const pb_variable_array<FieldT> input,
            const std::string &in_annotation_prefix=""):
            gadget<FieldT>(in_pb, FMT(in_annotation_prefix, " SharkMimc_gadget")),
            modulus(modulus), input(input)
    {
        sbox_vals.allocate(in_pb, num_branches + total_rounds * num_branches + num_branches, FMT(in_annotation_prefix, " sbox_vals"));

        linear_vals.allocate(in_pb, total_rounds * num_branches, FMT(in_annotation_prefix, " linear_vals"));
    }

    void prepare_round_constants() {
        for(uint32_t i = 0; i < num_round_constants; i++) {
            round_constants[i] = FieldT::random_element();
        }
    };

    void prepare_matrix(FieldT (&matrix)[num_branches][num_branches], uint64_t (&x)[num_branches],
            uint64_t (&y)[num_branches]) {

        // ASSUMING `FieldT` CAN FIT INTO A `ulong`
        ulong power = (modulus - 2).as_ulong();

        FieldT element = 0;
        FieldT base_temp = 0;
        uint64_t exp_temp = 0;
        for(uint32_t i = 0; i < this->num_branches; i++) {
            for (uint32_t j = 0; j < this->num_branches; j++) {
                element = x[i] + y[j];
                base_temp = element;
                exp_temp = power;
                element = 1;
                while(exp_temp > 0) {
                    if((exp_temp % 2) == 1) {
                        element *= base_temp;
                    }
                    base_temp *= base_temp;
                    exp_temp = exp_temp >> 1;
                }

                matrix[i][j] = element;
            }
        }

        /*for(uint32_t i = 0; i < this->num_branches; i++) {
            for (uint32_t j = 0; j < this->num_branches; j++) {
                cout << matrix[i][j] << " ";
            }
            cout << endl;
        }*/
    }

    // Note: This is just for benchmarking purposes. It might affect the correctness or security
    void prepare_matrix_random_vals(FieldT (&matrix)[num_branches][num_branches]) {
        for(uint32_t i = 0; i < this->num_branches; i++) {
            for (uint32_t j = 0; j < this->num_branches; j++) {
                matrix[i][j] = FieldT::random_element();
            }
        }
    }

    void prepare_matrix_1() {
        uint64_t x[num_branches] = {1, 2, 3, 4};
        uint64_t y[num_branches] = {5, 6, 7, 8};
//        prepare_matrix(matrix_1, x, y);
        prepare_matrix_random_vals(matrix_1);
    }

    void prepare_matrix_2() {
        uint64_t x[num_branches] = {9, 10, 11, 12};
        uint64_t y[num_branches] = {13, 14, 15, 16};
//        prepare_matrix(matrix_2, x, y);
        prepare_matrix_random_vals(matrix_2);
    }

    /*void prepare_round_keys() {
        // First t round keys are taken from the whole key
        for(uint32_t i = 0; i < this->num_branches; i++) {
            uint64_t l;
            memcpy(&l, this->key + (i * this->branch_size), this->branch_size);
            cout << "l is:" << l << endl;
            this->round_keys[i] = FieldT(l);
            cout << "round_keys is:" << round_keys[i] << endl;
        }
        uint32_t round_keys_offset = this->num_branches;
        uint32_t round_constants_offset = 0;

        // Calculate remaining round keys by using matrix M and round constants
        uint32_t num_rows_remaining = (this->num_round_keys - this->num_branches) / this->num_branches;
        for(uint32_t k = 0; k < num_rows_remaining; k++) {
            for (uint32_t i = 0; i < this->num_branches; i++) {
                for (uint32_t j = 0; j < this->num_branches; j++) {

                }
            }
        }
    }*/

    // Note: This is just for benchmarking purposes. It might affect the correctness or security
    void prepare_round_keys() {
        for(uint32_t i = 0; i < num_round_keys; i++) {
            round_keys[i] = FieldT::random_element();
        }
    }

    void generate_r1cs_constraints() {
        /*pb_variable_array<FieldT > value_branch;
        pb_variable_array<FieldT > value_branch_temp;
        pb_variable<FieldT> value_branch_temp_1;

        vector<FieldT> field_elems = this->input.get_vals(this->pb);
        cout << "field_elems size is " << field_elems.size() << endl;
        value_branch.resize(field_elems.size());
        value_branch.fill_with_field_elements(this->pb, field_elems);

        uint32_t round_keys_offset = 0;

        for(uint32_t k = 0; k < 3; k++) {
            // Add round key, S-box
            // 4 S-boxes, 8 constraints
            for(uint32_t i = 0; i < this->num_branches; i++) {
                auto t = value_branch[i] + round_keys[round_keys_offset++];
                this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldT>(t, t, value_branch_temp_1));
                this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldT>(value_branch_temp_1, t, value_branch[i]));
            }

            // Linear layer
            for(uint32_t j = 0; j < this->num_branches; j++) {
                for (uint32_t i = 0; i < this->num_branches; i++) {
                    auto temp1 = value_branch[j] * this->matrix_2[i][j];
                    *//*value_branch_temp[i]*//*auto t2  = value_branch_temp[i] + temp1;
                }
            }
        }*/

        /*auto bi = this->pb.val(this->input);
        auto bi1 = bi.as_bigint();
        cout << "N is " << bi1.N << endl;
        cout << "data[0] is " << bi1.data[0] << endl;
        cout << "data[1] is " << bi1.data[1] << endl;
        cout << "data[2] is " << bi1.data[2] << endl;
        cout << "data[3s] is " << bi1.data[3] << endl;*/
        /*for(uint32_t i = 0; i < this->num_branches; i++) {
            memcpy(value_branch[i], bi1 + (i * this->branch_size), this->branch_size);
        }*/
        /*libff::bit_vector bv = libff::convert_field_element_to_bit_vector<FieldT>(this->input);

        for(uint32_t i = 0; i < this->num_branches; i++) {
            memcpy(value_branch[i], bv + (i * this->branch_size), this->branch_size);
        }*/

        cout << "Entering generate_r1cs_constraints" << endl;

        pb_variable<FieldT> value_branch_temp_1;

        /*vector<FieldT> field_elems = this->input.get_vals(this->pb);
        cout << "field_elems size is " << field_elems.size() << endl;*/

        for(uint32_t i = 0; i < this->num_branches; i++) {
            sbox_vals[i] = this->input[i];
        }

        uint32_t round_no = 1;
        uint32_t round_keys_offset = 0;

        for(; round_no <= 3; round_no++) {
            uint32_t k = round_no * this->num_branches;

            // 4 S-boxes, 8 constraints
            for(uint32_t i = 0; i < this->num_branches; i++) {
                // Add round key
                auto t = sbox_vals[k+i-this->num_branches] + round_keys[round_keys_offset++];

                // S-box
                this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldT>(t, t, value_branch_temp_1));
                this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldT>(value_branch_temp_1, t, sbox_vals[k+i]));
            }

            // Linear layer
            for(uint32_t i = 0; i < this->num_branches; i++) {
                uint32_t j = round_no*this->num_branches + i;
                // linear_vals will be filled during generate witness
                sbox_vals[j] = linear_vals[j];
            }
        }

        for(; round_no <= 3+middle_rounds; round_no++) {

            uint32_t k = round_no * this->num_branches;

            // Add round key, only 1 `sbox_vals` is changed
            auto t = sbox_vals[k-this->num_branches] + round_keys[round_keys_offset];

            round_keys_offset += this->num_branches;

            // S-box
            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(t, t, value_branch_temp_1));
            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(value_branch_temp_1, t, sbox_vals[k-this->num_branches]));

            // Linear layer
            for(uint32_t i = 0; i < this->num_branches; i++) {
                uint32_t j = round_no*this->num_branches + i;
                // linear_vals will be filled during generate witness
                sbox_vals[j] = linear_vals[j];
            }
        }

        for(; round_no <= 3+middle_rounds+2; round_no++) {

            uint32_t k = round_no * this->num_branches;

            // 4 S-boxes, 8 constraints
            for(uint32_t i = 0; i < this->num_branches; i++) {
                // Add round key
                auto t = sbox_vals[k+i-this->num_branches] + round_keys[round_keys_offset++];

                // S-box
                this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldT>(t, t, value_branch_temp_1));
                this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldT>(value_branch_temp_1, t, sbox_vals[k+i]));
            }

            // Linear layer
            for(uint32_t i = 0; i < this->num_branches; i++) {
                uint32_t j = round_no*this->num_branches + i;
                // linear_vals will be filled during generate witness
                sbox_vals[j] = linear_vals[j];
            }
        }

        for(uint32_t i = 0; i < this->num_branches; i++) {
            // Add round key
            auto t = sbox_vals[round_no*this->num_branches+i-this->num_branches] + round_keys[round_keys_offset++];

            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(t, t, value_branch_temp_1));
            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(value_branch_temp_1, t, sbox_vals[round_no*this->num_branches+i]));
        }

        cout << "Leaving generate_r1cs_constraints" << endl;
    }

    void generate_r1cs_witness() {

        cout << "Entering generate_r1cs_witness" << endl;

        vector<FieldT> field_elems = this->input.get_vals(this->pb);
        cout << "field_elems size is " << field_elems.size() << endl;

        for(uint32_t i = 0; i < this->num_branches; i++) {
            this->pb.val(sbox_vals[i]) = field_elems[i];
        }

        uint32_t round_no = 1;
        uint32_t round_keys_offset = 0;

        for(; round_no <= 3; round_no++) {

            round_keys_offset += this->num_branches;

            for(uint32_t j = 0; j < this->num_branches; j++) {
                uint32_t k = round_no*this->num_branches + j;
                for (uint32_t i = 0; i < this->num_branches; i++) {
                    uint32_t l = round_no*this->num_branches + i;
                    auto t = this->pb.val(sbox_vals[k]) * this->matrix_2[i][j];
                    this->pb.val(linear_vals[l]) = this->pb.val(linear_vals[l]) + t;
                }
            }
        }

        for(; round_no <= 3+middle_rounds; round_no++) {

            // 0th index is changed by S-Box
            for (uint32_t i = 1; i < this->num_branches; i++) {
                uint32_t k = round_no*this->num_branches + i;
                this->pb.val(sbox_vals[k]) = this->pb.val(sbox_vals[k-this->num_branches]) + round_keys[round_keys_offset++];
            }

            for(uint32_t j = 0; j < this->num_branches; j++) {
                uint32_t k = round_no*this->num_branches + j;
                for (uint32_t i = 0; i < this->num_branches; i++) {
                    uint32_t l = round_no*this->num_branches + i;
                    auto t = this->pb.val(sbox_vals[k]) * this->matrix_2[i][j];
                    this->pb.val(linear_vals[l]) = this->pb.val(linear_vals[l]) + t;
                }
            }
        }

        for(; round_no <= 3+middle_rounds+2; round_no++) {
            round_keys_offset += this->num_branches;

            for(uint32_t j = 0; j < this->num_branches; j++) {
                uint32_t k = round_no*this->num_branches + j;
                for (uint32_t i = 0; i < this->num_branches; i++) {
                    uint32_t l = round_no*this->num_branches + i;
                    auto t = this->pb.val(sbox_vals[k]) * this->matrix_2[i][j];
                    this->pb.val(linear_vals[l]) = this->pb.val(linear_vals[l]) + t;
                }
            }
        }

        for(uint32_t i = 0; i < this->num_branches; i++) {
            uint32_t k = round_no * this->num_branches + i;
            this->pb.val(sbox_vals[k]) = this->pb.val(sbox_vals[k]) + round_keys[round_keys_offset++];
        }

        cout << "Leaving generate_r1cs_witness" << endl;
    }
};