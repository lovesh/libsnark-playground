#include <fstream>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libff/algebra/curves/public_params.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

template<typename ppT>
void print_vk_to_file(r1cs_ppzksnark_verification_key<ppT> vk, string pathToFile)
{
  ofstream vk_data;
  vk_data.open(pathToFile);

  G2<ppT> A(vk.alphaA_g2);
  A.to_affine_coordinates();
  G1<ppT> B(vk.alphaB_g1);
  B.to_affine_coordinates();
  G2<ppT> C(vk.alphaC_g2);
  C.to_affine_coordinates();

  G2<ppT> gamma(vk.gamma_g2);
  gamma.to_affine_coordinates();
  G1<ppT> gamma_beta_1(vk.gamma_beta_g1);
  gamma_beta_1.to_affine_coordinates();
  G2<ppT> gamma_beta_2(vk.gamma_beta_g2);
  gamma_beta_2.to_affine_coordinates();

  G2<ppT> Z(vk.rC_Z_g2);
  Z.to_affine_coordinates();

  accumulation_vector<G1<ppT>> IC(vk.encoded_IC_query);
  G1<ppT> IC_0(IC.first);
  IC_0.to_affine_coordinates();

  vk_data << A.coord[0] << endl;
  vk_data << A.coord[1] << endl;

  vk_data << B.coord[0] << endl;
  vk_data << B.coord[1] << endl;

  vk_data << C.coord[0] << endl;
  vk_data << C.coord[1] << endl;

  vk_data << gamma.coord[0] << endl;
  vk_data << gamma.coord[1] << endl;

  vk_data << gamma_beta_1.coord[0] << endl;
  vk_data << gamma_beta_1.coord[1] << endl;

  vk_data << gamma_beta_2.coord[0] << endl;
  vk_data << gamma_beta_2.coord[1] << endl;

  vk_data << Z.coord[0] << endl;
  vk_data << Z.coord[1] << endl;

  vk_data << IC_0.coord[0] << endl;
  vk_data << IC_0.coord[1] << endl;

  for(size_t i=0; i<IC.size(); i++) {
    G1<ppT> IC_N(IC.rest[i]);
    IC_N.to_affine_coordinates();
    vk_data << IC_N.coord[0] << endl;
    vk_data << IC_N.coord[1] << endl;
  }

  vk_data.close();
}

template<typename ppT>
void print_proof_to_file(r1cs_ppzksnark_proof<ppT> proof, string pathToFile)
{
  ofstream proof_data;
  proof_data.open(pathToFile);

  G1<ppT> A_g(proof.g_A.g);
  A_g.to_affine_coordinates();
  G1<ppT> A_h(proof.g_A.h);
  A_h.to_affine_coordinates();

  G2<ppT> B_g(proof.g_B.g);
  B_g.to_affine_coordinates();
  G1<ppT> B_h(proof.g_B.h);
  B_h.to_affine_coordinates();

  G1<ppT> C_g(proof.g_C.g);
  C_g.to_affine_coordinates();
  G1<ppT> C_h(proof.g_C.h);
  C_h.to_affine_coordinates();

  G1<ppT> H(proof.g_H);
  H.to_affine_coordinates();
  G1<ppT> K(proof.g_K);
  K.to_affine_coordinates();

  proof_data << A_g.coord[0] << endl;
  proof_data << A_g.coord[1] << endl;

  proof_data << A_h.coord[0] << endl;
  proof_data << A_h.coord[1] << endl;

  proof_data << B_g.coord[0] << endl;
  proof_data << B_g.coord[1] << endl;

  proof_data << B_h.coord[0] << endl;
  proof_data << B_h.coord[1] << endl;

  proof_data << C_g.coord[0] << endl;
  proof_data << C_g.coord[1] << endl;

  proof_data << C_h.coord[0] << endl;
  proof_data << C_h.coord[1] << endl;

  proof_data << H.coord[0] << endl;
  proof_data << H.coord[1] << endl;

  proof_data << K.coord[0] << endl;
  proof_data << K.coord[1] << endl;

  proof_data.close();
}