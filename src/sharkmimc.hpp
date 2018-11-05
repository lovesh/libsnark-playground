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
    static const uint32_t total_rounds = 3 + middle_rounds + 3;
    static const uint32_t num_round_keys = (middle_rounds + 7) * num_branches;
    static const uint32_t num_round_constants = (middle_rounds + 6) * num_branches;
    const FieldT modulus;
    FieldT matrix_1[num_branches][num_branches];
    FieldT matrix_2[num_branches][num_branches];
    pb_variable_array<FieldT> sbox_vals;
    pb_variable_array<FieldT> round_squares;
    pb_variable_array<FieldT> sbox_outs;
public:
    FieldT round_constants[num_round_constants];
    FieldT round_keys[num_round_keys];
    const pb_variable_array<FieldT> input;
    pb_variable_array<FieldT> output;

    SharkMimc_gadget(FieldT modulus, protoboard<FieldT> &in_pb, const pb_variable_array<FieldT> input,
            const std::string &in_annotation_prefix=""):
            gadget<FieldT>(in_pb, FMT(in_annotation_prefix, " SharkMimc_gadget")),
            modulus(modulus), input(input)
    {
        sbox_vals.allocate(in_pb, num_branches + 3 * num_branches + middle_rounds * num_branches + 2 * num_branches + num_branches, FMT(in_annotation_prefix, " sbox_vals"));

        round_squares.allocate(in_pb, 3 * num_branches + middle_rounds + 2 * num_branches + num_branches, FMT(in_annotation_prefix, " round_squares"));

        sbox_outs.allocate(in_pb, 3 * num_branches + middle_rounds + 2 * num_branches + num_branches, FMT(in_annotation_prefix, " sbox_outs"));

        output.allocate(in_pb, this->num_branches, FMT(in_annotation_prefix, " output"));
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

    const pb_variable_array<FieldT>& result() const
    {
        return output;
    }

    void generate_r1cs_constraints() {

        for(uint32_t i = 0; i < this->num_branches; i++) {
            sbox_vals[i] = this->input[i];
        }

        uint32_t round_no = 1;
        uint32_t round_keys_offset = 0;
        uint32_t round_squares_idx = 0;
        uint32_t sbox_outs_idx = 0;

        for(; round_no <= 3; round_no++) {
            uint32_t offset = round_no * this->num_branches;
            uint32_t prev_offset = offset - this->num_branches;
            // 4 S-boxes, 8 constraints
            for(uint32_t i = 0; i < this->num_branches; i++) {

                // Add round key
                auto t = sbox_vals[prev_offset+i] + round_keys[round_keys_offset++];

                // S-box
                this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldT>(t, t, round_squares[round_squares_idx]));
                this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldT>(round_squares[round_squares_idx], t, sbox_outs[sbox_outs_idx++]));
                round_squares_idx++;
            }
        }

        for(; round_no <= 3+middle_rounds; round_no++) {

            uint32_t offset = round_no * this->num_branches;

            // Add round key, only 1 `sbox_vals` is changed
            auto t = sbox_vals[offset-this->num_branches] + round_keys[round_keys_offset];

            round_keys_offset += this->num_branches;

            // S-box
            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(t, t, round_squares[round_squares_idx]));
            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(round_squares[round_squares_idx], t, sbox_outs[sbox_outs_idx++]));
            round_squares_idx++;
        }

        for(; round_no <= 3+middle_rounds+2; round_no++) {

            uint32_t offset = round_no * this->num_branches;
            uint32_t prev_offset = offset - this->num_branches;

            // 4 S-boxes, 8 constraints
            for(uint32_t i = 0; i < this->num_branches; i++) {

                // Add round key
                auto t = sbox_vals[prev_offset+i] + round_keys[round_keys_offset++];

                // S-box
                this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldT>(t, t, round_squares[round_squares_idx]));
                this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldT>(round_squares[round_squares_idx], t, sbox_outs[sbox_outs_idx++]));
                round_squares_idx++;
            }
        }

        uint32_t offset = round_no * this->num_branches;
        uint32_t prev_offset = offset - this->num_branches;

        for(uint32_t i = 0; i < this->num_branches; i++) {

            // Add round key
            auto t = sbox_vals[prev_offset+i] + round_keys[round_keys_offset++];

            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(t, t, round_squares[round_squares_idx]));
            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(round_squares[round_squares_idx], t, sbox_outs[sbox_outs_idx++]));
            round_squares_idx++;
            round_keys_offset++;
        }

        cout << "sbox_outs_idx is " << sbox_outs_idx << endl;
    }

    void generate_r1cs_witness() {

        vector<FieldT> field_elems = this->input.get_vals(this->pb);

        for(uint32_t i = 0; i < this->num_branches; i++) {
            this->pb.val(sbox_vals[i]) = field_elems[i];
        }

        uint32_t round_no = 1;
        uint32_t round_keys_offset = 0;
        uint32_t round_squares_idx = 0;
        uint32_t sbox_outs_idx = 0;

        for(; round_no <= 3; round_no++) {

            uint32_t offset = round_no * this->num_branches;
            uint32_t prev_offset = offset - this->num_branches;

            vector<FieldT> linear(this->num_branches, 0);

            for(uint32_t j = 0; j < this->num_branches; j++) {

                auto t = this->pb.val(sbox_vals[prev_offset+j]) + round_keys[round_keys_offset++];

                this->pb.val(round_squares[round_squares_idx]) = t * t;
                this->pb.val(sbox_outs[sbox_outs_idx]) = this->pb.val(round_squares[round_squares_idx]) * t;

                auto s = this->pb.val(sbox_outs[sbox_outs_idx++]);

                for (uint32_t i = 0; i < this->num_branches; i++) {
                    auto temp = s * this->matrix_2[i][j];
                    linear[i] = linear[i] + temp;
                }
                round_squares_idx++;
            }

            for(uint32_t j = 0; j < this->num_branches; j++) {
                this->pb.val(sbox_vals[offset+j]) = linear[j];
            }
        }

        for(; round_no <= 3+middle_rounds; round_no++) {

            uint32_t offset = round_no * this->num_branches;
            uint32_t prev_offset = offset - this->num_branches;

            auto t = this->pb.val(sbox_vals[prev_offset]) + round_keys[round_keys_offset++];

            this->pb.val(round_squares[round_squares_idx]) = t * t;
            this->pb.val(sbox_outs[sbox_outs_idx]) = this->pb.val(round_squares[round_squares_idx]) * t;

            vector<FieldT> linear(this->num_branches, 0);

            for(uint32_t j = 0; j < this->num_branches; j++) {
                auto s = j == 0? this->pb.val(sbox_outs[sbox_outs_idx++]): (this->pb.val(sbox_vals[prev_offset+j]) + round_keys[round_keys_offset++]);

                for (uint32_t i = 0; i < this->num_branches; i++) {
                    auto temp = s * this->matrix_2[i][j];
                    linear[i] = linear[i] + temp;
                }
            }

            for(uint32_t j = 0; j < this->num_branches; j++) {
                this->pb.val(sbox_vals[offset+j]) = linear[j];
            }

            round_squares_idx++;
        }

        for(; round_no <= 3+middle_rounds+2; round_no++) {

            uint32_t offset = round_no * this->num_branches;
            uint32_t prev_offset = offset - this->num_branches;

            vector<FieldT> linear(this->num_branches, 0);

            for(uint32_t j = 0; j < this->num_branches; j++) {

                auto t = this->pb.val(sbox_vals[prev_offset+j]) + round_keys[round_keys_offset++];

                this->pb.val(round_squares[round_squares_idx]) = t * t;
                this->pb.val(sbox_outs[sbox_outs_idx]) = this->pb.val(round_squares[round_squares_idx]) * t;

                auto s = this->pb.val(sbox_outs[sbox_outs_idx++]);

                for (uint32_t i = 0; i < this->num_branches; i++) {
                    auto temp = s * this->matrix_2[i][j];
                    linear[i] = linear[i] + temp;
                }

                round_squares_idx++;
            }

            for(uint32_t j = 0; j < this->num_branches; j++) {
                this->pb.val(sbox_vals[offset+j]) = linear[j];
            }
        }

        uint32_t offset = round_no * this->num_branches;
        uint32_t prev_offset = offset - this->num_branches;

        for(uint32_t i = 0; i < this->num_branches; i++) {
            uint32_t k = offset + i;

            auto t = this->pb.val(sbox_vals[prev_offset+i]) + round_keys[round_keys_offset++];

            this->pb.val(round_squares[round_squares_idx]) = t * t;
            this->pb.val(sbox_outs[sbox_outs_idx]) = this->pb.val(round_squares[round_squares_idx]) * t;

            this->pb.val(sbox_vals[k]) = this->pb.val(sbox_outs[sbox_outs_idx++]) + round_keys[round_keys_offset++];

            round_squares_idx++;
        }

        offset = sbox_vals.size() - this->num_branches;

        for(uint32_t i = 0; i < this->num_branches; i++) {
            this->pb.val(output[i]) = this->pb.val(sbox_vals[offset+i]);
        }

    }

};