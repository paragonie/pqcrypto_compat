<?php
declare(strict_types=1);
namespace ParagonIE\PQCrypto\Internal\MLDSA;

use ArrayAccess;
use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Internal\Object256;

class Ring extends Object256 implements ArrayAccess
{
    public static function zero(): self
    {
        return new Ring();
    }

    public function add(Ring $other): Ring
    {
        $r = new Ring();
        $r->c0 = Field::add($this->c0, $other->c0);
        $r->c1 = Field::add($this->c1, $other->c1);
        $r->c2 = Field::add($this->c2, $other->c2);
        $r->c3 = Field::add($this->c3, $other->c3);
        $r->c4 = Field::add($this->c4, $other->c4);
        $r->c5 = Field::add($this->c5, $other->c5);
        $r->c6 = Field::add($this->c6, $other->c6);
        $r->c7 = Field::add($this->c7, $other->c7);
        $r->c8 = Field::add($this->c8, $other->c8);
        $r->c9 = Field::add($this->c9, $other->c9);
        $r->c10 = Field::add($this->c10, $other->c10);
        $r->c11 = Field::add($this->c11, $other->c11);
        $r->c12 = Field::add($this->c12, $other->c12);
        $r->c13 = Field::add($this->c13, $other->c13);
        $r->c14 = Field::add($this->c14, $other->c14);
        $r->c15 = Field::add($this->c15, $other->c15);
        $r->c16 = Field::add($this->c16, $other->c16);
        $r->c17 = Field::add($this->c17, $other->c17);
        $r->c18 = Field::add($this->c18, $other->c18);
        $r->c19 = Field::add($this->c19, $other->c19);
        $r->c20 = Field::add($this->c20, $other->c20);
        $r->c21 = Field::add($this->c21, $other->c21);
        $r->c22 = Field::add($this->c22, $other->c22);
        $r->c23 = Field::add($this->c23, $other->c23);
        $r->c24 = Field::add($this->c24, $other->c24);
        $r->c25 = Field::add($this->c25, $other->c25);
        $r->c26 = Field::add($this->c26, $other->c26);
        $r->c27 = Field::add($this->c27, $other->c27);
        $r->c28 = Field::add($this->c28, $other->c28);
        $r->c29 = Field::add($this->c29, $other->c29);
        $r->c30 = Field::add($this->c30, $other->c30);
        $r->c31 = Field::add($this->c31, $other->c31);
        $r->c32 = Field::add($this->c32, $other->c32);
        $r->c33 = Field::add($this->c33, $other->c33);
        $r->c34 = Field::add($this->c34, $other->c34);
        $r->c35 = Field::add($this->c35, $other->c35);
        $r->c36 = Field::add($this->c36, $other->c36);
        $r->c37 = Field::add($this->c37, $other->c37);
        $r->c38 = Field::add($this->c38, $other->c38);
        $r->c39 = Field::add($this->c39, $other->c39);
        $r->c40 = Field::add($this->c40, $other->c40);
        $r->c41 = Field::add($this->c41, $other->c41);
        $r->c42 = Field::add($this->c42, $other->c42);
        $r->c43 = Field::add($this->c43, $other->c43);
        $r->c44 = Field::add($this->c44, $other->c44);
        $r->c45 = Field::add($this->c45, $other->c45);
        $r->c46 = Field::add($this->c46, $other->c46);
        $r->c47 = Field::add($this->c47, $other->c47);
        $r->c48 = Field::add($this->c48, $other->c48);
        $r->c49 = Field::add($this->c49, $other->c49);
        $r->c50 = Field::add($this->c50, $other->c50);
        $r->c51 = Field::add($this->c51, $other->c51);
        $r->c52 = Field::add($this->c52, $other->c52);
        $r->c53 = Field::add($this->c53, $other->c53);
        $r->c54 = Field::add($this->c54, $other->c54);
        $r->c55 = Field::add($this->c55, $other->c55);
        $r->c56 = Field::add($this->c56, $other->c56);
        $r->c57 = Field::add($this->c57, $other->c57);
        $r->c58 = Field::add($this->c58, $other->c58);
        $r->c59 = Field::add($this->c59, $other->c59);
        $r->c60 = Field::add($this->c60, $other->c60);
        $r->c61 = Field::add($this->c61, $other->c61);
        $r->c62 = Field::add($this->c62, $other->c62);
        $r->c63 = Field::add($this->c63, $other->c63);
        $r->c64 = Field::add($this->c64, $other->c64);
        $r->c65 = Field::add($this->c65, $other->c65);
        $r->c66 = Field::add($this->c66, $other->c66);
        $r->c67 = Field::add($this->c67, $other->c67);
        $r->c68 = Field::add($this->c68, $other->c68);
        $r->c69 = Field::add($this->c69, $other->c69);
        $r->c70 = Field::add($this->c70, $other->c70);
        $r->c71 = Field::add($this->c71, $other->c71);
        $r->c72 = Field::add($this->c72, $other->c72);
        $r->c73 = Field::add($this->c73, $other->c73);
        $r->c74 = Field::add($this->c74, $other->c74);
        $r->c75 = Field::add($this->c75, $other->c75);
        $r->c76 = Field::add($this->c76, $other->c76);
        $r->c77 = Field::add($this->c77, $other->c77);
        $r->c78 = Field::add($this->c78, $other->c78);
        $r->c79 = Field::add($this->c79, $other->c79);
        $r->c80 = Field::add($this->c80, $other->c80);
        $r->c81 = Field::add($this->c81, $other->c81);
        $r->c82 = Field::add($this->c82, $other->c82);
        $r->c83 = Field::add($this->c83, $other->c83);
        $r->c84 = Field::add($this->c84, $other->c84);
        $r->c85 = Field::add($this->c85, $other->c85);
        $r->c86 = Field::add($this->c86, $other->c86);
        $r->c87 = Field::add($this->c87, $other->c87);
        $r->c88 = Field::add($this->c88, $other->c88);
        $r->c89 = Field::add($this->c89, $other->c89);
        $r->c90 = Field::add($this->c90, $other->c90);
        $r->c91 = Field::add($this->c91, $other->c91);
        $r->c92 = Field::add($this->c92, $other->c92);
        $r->c93 = Field::add($this->c93, $other->c93);
        $r->c94 = Field::add($this->c94, $other->c94);
        $r->c95 = Field::add($this->c95, $other->c95);
        $r->c96 = Field::add($this->c96, $other->c96);
        $r->c97 = Field::add($this->c97, $other->c97);
        $r->c98 = Field::add($this->c98, $other->c98);
        $r->c99 = Field::add($this->c99, $other->c99);
        $r->c100 = Field::add($this->c100, $other->c100);
        $r->c101 = Field::add($this->c101, $other->c101);
        $r->c102 = Field::add($this->c102, $other->c102);
        $r->c103 = Field::add($this->c103, $other->c103);
        $r->c104 = Field::add($this->c104, $other->c104);
        $r->c105 = Field::add($this->c105, $other->c105);
        $r->c106 = Field::add($this->c106, $other->c106);
        $r->c107 = Field::add($this->c107, $other->c107);
        $r->c108 = Field::add($this->c108, $other->c108);
        $r->c109 = Field::add($this->c109, $other->c109);
        $r->c110 = Field::add($this->c110, $other->c110);
        $r->c111 = Field::add($this->c111, $other->c111);
        $r->c112 = Field::add($this->c112, $other->c112);
        $r->c113 = Field::add($this->c113, $other->c113);
        $r->c114 = Field::add($this->c114, $other->c114);
        $r->c115 = Field::add($this->c115, $other->c115);
        $r->c116 = Field::add($this->c116, $other->c116);
        $r->c117 = Field::add($this->c117, $other->c117);
        $r->c118 = Field::add($this->c118, $other->c118);
        $r->c119 = Field::add($this->c119, $other->c119);
        $r->c120 = Field::add($this->c120, $other->c120);
        $r->c121 = Field::add($this->c121, $other->c121);
        $r->c122 = Field::add($this->c122, $other->c122);
        $r->c123 = Field::add($this->c123, $other->c123);
        $r->c124 = Field::add($this->c124, $other->c124);
        $r->c125 = Field::add($this->c125, $other->c125);
        $r->c126 = Field::add($this->c126, $other->c126);
        $r->c127 = Field::add($this->c127, $other->c127);
        $r->c128 = Field::add($this->c128, $other->c128);
        $r->c129 = Field::add($this->c129, $other->c129);
        $r->c130 = Field::add($this->c130, $other->c130);
        $r->c131 = Field::add($this->c131, $other->c131);
        $r->c132 = Field::add($this->c132, $other->c132);
        $r->c133 = Field::add($this->c133, $other->c133);
        $r->c134 = Field::add($this->c134, $other->c134);
        $r->c135 = Field::add($this->c135, $other->c135);
        $r->c136 = Field::add($this->c136, $other->c136);
        $r->c137 = Field::add($this->c137, $other->c137);
        $r->c138 = Field::add($this->c138, $other->c138);
        $r->c139 = Field::add($this->c139, $other->c139);
        $r->c140 = Field::add($this->c140, $other->c140);
        $r->c141 = Field::add($this->c141, $other->c141);
        $r->c142 = Field::add($this->c142, $other->c142);
        $r->c143 = Field::add($this->c143, $other->c143);
        $r->c144 = Field::add($this->c144, $other->c144);
        $r->c145 = Field::add($this->c145, $other->c145);
        $r->c146 = Field::add($this->c146, $other->c146);
        $r->c147 = Field::add($this->c147, $other->c147);
        $r->c148 = Field::add($this->c148, $other->c148);
        $r->c149 = Field::add($this->c149, $other->c149);
        $r->c150 = Field::add($this->c150, $other->c150);
        $r->c151 = Field::add($this->c151, $other->c151);
        $r->c152 = Field::add($this->c152, $other->c152);
        $r->c153 = Field::add($this->c153, $other->c153);
        $r->c154 = Field::add($this->c154, $other->c154);
        $r->c155 = Field::add($this->c155, $other->c155);
        $r->c156 = Field::add($this->c156, $other->c156);
        $r->c157 = Field::add($this->c157, $other->c157);
        $r->c158 = Field::add($this->c158, $other->c158);
        $r->c159 = Field::add($this->c159, $other->c159);
        $r->c160 = Field::add($this->c160, $other->c160);
        $r->c161 = Field::add($this->c161, $other->c161);
        $r->c162 = Field::add($this->c162, $other->c162);
        $r->c163 = Field::add($this->c163, $other->c163);
        $r->c164 = Field::add($this->c164, $other->c164);
        $r->c165 = Field::add($this->c165, $other->c165);
        $r->c166 = Field::add($this->c166, $other->c166);
        $r->c167 = Field::add($this->c167, $other->c167);
        $r->c168 = Field::add($this->c168, $other->c168);
        $r->c169 = Field::add($this->c169, $other->c169);
        $r->c170 = Field::add($this->c170, $other->c170);
        $r->c171 = Field::add($this->c171, $other->c171);
        $r->c172 = Field::add($this->c172, $other->c172);
        $r->c173 = Field::add($this->c173, $other->c173);
        $r->c174 = Field::add($this->c174, $other->c174);
        $r->c175 = Field::add($this->c175, $other->c175);
        $r->c176 = Field::add($this->c176, $other->c176);
        $r->c177 = Field::add($this->c177, $other->c177);
        $r->c178 = Field::add($this->c178, $other->c178);
        $r->c179 = Field::add($this->c179, $other->c179);
        $r->c180 = Field::add($this->c180, $other->c180);
        $r->c181 = Field::add($this->c181, $other->c181);
        $r->c182 = Field::add($this->c182, $other->c182);
        $r->c183 = Field::add($this->c183, $other->c183);
        $r->c184 = Field::add($this->c184, $other->c184);
        $r->c185 = Field::add($this->c185, $other->c185);
        $r->c186 = Field::add($this->c186, $other->c186);
        $r->c187 = Field::add($this->c187, $other->c187);
        $r->c188 = Field::add($this->c188, $other->c188);
        $r->c189 = Field::add($this->c189, $other->c189);
        $r->c190 = Field::add($this->c190, $other->c190);
        $r->c191 = Field::add($this->c191, $other->c191);
        $r->c192 = Field::add($this->c192, $other->c192);
        $r->c193 = Field::add($this->c193, $other->c193);
        $r->c194 = Field::add($this->c194, $other->c194);
        $r->c195 = Field::add($this->c195, $other->c195);
        $r->c196 = Field::add($this->c196, $other->c196);
        $r->c197 = Field::add($this->c197, $other->c197);
        $r->c198 = Field::add($this->c198, $other->c198);
        $r->c199 = Field::add($this->c199, $other->c199);
        $r->c200 = Field::add($this->c200, $other->c200);
        $r->c201 = Field::add($this->c201, $other->c201);
        $r->c202 = Field::add($this->c202, $other->c202);
        $r->c203 = Field::add($this->c203, $other->c203);
        $r->c204 = Field::add($this->c204, $other->c204);
        $r->c205 = Field::add($this->c205, $other->c205);
        $r->c206 = Field::add($this->c206, $other->c206);
        $r->c207 = Field::add($this->c207, $other->c207);
        $r->c208 = Field::add($this->c208, $other->c208);
        $r->c209 = Field::add($this->c209, $other->c209);
        $r->c210 = Field::add($this->c210, $other->c210);
        $r->c211 = Field::add($this->c211, $other->c211);
        $r->c212 = Field::add($this->c212, $other->c212);
        $r->c213 = Field::add($this->c213, $other->c213);
        $r->c214 = Field::add($this->c214, $other->c214);
        $r->c215 = Field::add($this->c215, $other->c215);
        $r->c216 = Field::add($this->c216, $other->c216);
        $r->c217 = Field::add($this->c217, $other->c217);
        $r->c218 = Field::add($this->c218, $other->c218);
        $r->c219 = Field::add($this->c219, $other->c219);
        $r->c220 = Field::add($this->c220, $other->c220);
        $r->c221 = Field::add($this->c221, $other->c221);
        $r->c222 = Field::add($this->c222, $other->c222);
        $r->c223 = Field::add($this->c223, $other->c223);
        $r->c224 = Field::add($this->c224, $other->c224);
        $r->c225 = Field::add($this->c225, $other->c225);
        $r->c226 = Field::add($this->c226, $other->c226);
        $r->c227 = Field::add($this->c227, $other->c227);
        $r->c228 = Field::add($this->c228, $other->c228);
        $r->c229 = Field::add($this->c229, $other->c229);
        $r->c230 = Field::add($this->c230, $other->c230);
        $r->c231 = Field::add($this->c231, $other->c231);
        $r->c232 = Field::add($this->c232, $other->c232);
        $r->c233 = Field::add($this->c233, $other->c233);
        $r->c234 = Field::add($this->c234, $other->c234);
        $r->c235 = Field::add($this->c235, $other->c235);
        $r->c236 = Field::add($this->c236, $other->c236);
        $r->c237 = Field::add($this->c237, $other->c237);
        $r->c238 = Field::add($this->c238, $other->c238);
        $r->c239 = Field::add($this->c239, $other->c239);
        $r->c240 = Field::add($this->c240, $other->c240);
        $r->c241 = Field::add($this->c241, $other->c241);
        $r->c242 = Field::add($this->c242, $other->c242);
        $r->c243 = Field::add($this->c243, $other->c243);
        $r->c244 = Field::add($this->c244, $other->c244);
        $r->c245 = Field::add($this->c245, $other->c245);
        $r->c246 = Field::add($this->c246, $other->c246);
        $r->c247 = Field::add($this->c247, $other->c247);
        $r->c248 = Field::add($this->c248, $other->c248);
        $r->c249 = Field::add($this->c249, $other->c249);
        $r->c250 = Field::add($this->c250, $other->c250);
        $r->c251 = Field::add($this->c251, $other->c251);
        $r->c252 = Field::add($this->c252, $other->c252);
        $r->c253 = Field::add($this->c253, $other->c253);
        $r->c254 = Field::add($this->c254, $other->c254);
        $r->c255 = Field::add($this->c255, $other->c255);
        return $r;
    }

    public function sub(Ring $other): Ring
    {
        $r = new Ring();
        $r->c0 = Field::sub($this->c0, $other->c0);
        $r->c1 = Field::sub($this->c1, $other->c1);
        $r->c2 = Field::sub($this->c2, $other->c2);
        $r->c3 = Field::sub($this->c3, $other->c3);
        $r->c4 = Field::sub($this->c4, $other->c4);
        $r->c5 = Field::sub($this->c5, $other->c5);
        $r->c6 = Field::sub($this->c6, $other->c6);
        $r->c7 = Field::sub($this->c7, $other->c7);
        $r->c8 = Field::sub($this->c8, $other->c8);
        $r->c9 = Field::sub($this->c9, $other->c9);
        $r->c10 = Field::sub($this->c10, $other->c10);
        $r->c11 = Field::sub($this->c11, $other->c11);
        $r->c12 = Field::sub($this->c12, $other->c12);
        $r->c13 = Field::sub($this->c13, $other->c13);
        $r->c14 = Field::sub($this->c14, $other->c14);
        $r->c15 = Field::sub($this->c15, $other->c15);
        $r->c16 = Field::sub($this->c16, $other->c16);
        $r->c17 = Field::sub($this->c17, $other->c17);
        $r->c18 = Field::sub($this->c18, $other->c18);
        $r->c19 = Field::sub($this->c19, $other->c19);
        $r->c20 = Field::sub($this->c20, $other->c20);
        $r->c21 = Field::sub($this->c21, $other->c21);
        $r->c22 = Field::sub($this->c22, $other->c22);
        $r->c23 = Field::sub($this->c23, $other->c23);
        $r->c24 = Field::sub($this->c24, $other->c24);
        $r->c25 = Field::sub($this->c25, $other->c25);
        $r->c26 = Field::sub($this->c26, $other->c26);
        $r->c27 = Field::sub($this->c27, $other->c27);
        $r->c28 = Field::sub($this->c28, $other->c28);
        $r->c29 = Field::sub($this->c29, $other->c29);
        $r->c30 = Field::sub($this->c30, $other->c30);
        $r->c31 = Field::sub($this->c31, $other->c31);
        $r->c32 = Field::sub($this->c32, $other->c32);
        $r->c33 = Field::sub($this->c33, $other->c33);
        $r->c34 = Field::sub($this->c34, $other->c34);
        $r->c35 = Field::sub($this->c35, $other->c35);
        $r->c36 = Field::sub($this->c36, $other->c36);
        $r->c37 = Field::sub($this->c37, $other->c37);
        $r->c38 = Field::sub($this->c38, $other->c38);
        $r->c39 = Field::sub($this->c39, $other->c39);
        $r->c40 = Field::sub($this->c40, $other->c40);
        $r->c41 = Field::sub($this->c41, $other->c41);
        $r->c42 = Field::sub($this->c42, $other->c42);
        $r->c43 = Field::sub($this->c43, $other->c43);
        $r->c44 = Field::sub($this->c44, $other->c44);
        $r->c45 = Field::sub($this->c45, $other->c45);
        $r->c46 = Field::sub($this->c46, $other->c46);
        $r->c47 = Field::sub($this->c47, $other->c47);
        $r->c48 = Field::sub($this->c48, $other->c48);
        $r->c49 = Field::sub($this->c49, $other->c49);
        $r->c50 = Field::sub($this->c50, $other->c50);
        $r->c51 = Field::sub($this->c51, $other->c51);
        $r->c52 = Field::sub($this->c52, $other->c52);
        $r->c53 = Field::sub($this->c53, $other->c53);
        $r->c54 = Field::sub($this->c54, $other->c54);
        $r->c55 = Field::sub($this->c55, $other->c55);
        $r->c56 = Field::sub($this->c56, $other->c56);
        $r->c57 = Field::sub($this->c57, $other->c57);
        $r->c58 = Field::sub($this->c58, $other->c58);
        $r->c59 = Field::sub($this->c59, $other->c59);
        $r->c60 = Field::sub($this->c60, $other->c60);
        $r->c61 = Field::sub($this->c61, $other->c61);
        $r->c62 = Field::sub($this->c62, $other->c62);
        $r->c63 = Field::sub($this->c63, $other->c63);
        $r->c64 = Field::sub($this->c64, $other->c64);
        $r->c65 = Field::sub($this->c65, $other->c65);
        $r->c66 = Field::sub($this->c66, $other->c66);
        $r->c67 = Field::sub($this->c67, $other->c67);
        $r->c68 = Field::sub($this->c68, $other->c68);
        $r->c69 = Field::sub($this->c69, $other->c69);
        $r->c70 = Field::sub($this->c70, $other->c70);
        $r->c71 = Field::sub($this->c71, $other->c71);
        $r->c72 = Field::sub($this->c72, $other->c72);
        $r->c73 = Field::sub($this->c73, $other->c73);
        $r->c74 = Field::sub($this->c74, $other->c74);
        $r->c75 = Field::sub($this->c75, $other->c75);
        $r->c76 = Field::sub($this->c76, $other->c76);
        $r->c77 = Field::sub($this->c77, $other->c77);
        $r->c78 = Field::sub($this->c78, $other->c78);
        $r->c79 = Field::sub($this->c79, $other->c79);
        $r->c80 = Field::sub($this->c80, $other->c80);
        $r->c81 = Field::sub($this->c81, $other->c81);
        $r->c82 = Field::sub($this->c82, $other->c82);
        $r->c83 = Field::sub($this->c83, $other->c83);
        $r->c84 = Field::sub($this->c84, $other->c84);
        $r->c85 = Field::sub($this->c85, $other->c85);
        $r->c86 = Field::sub($this->c86, $other->c86);
        $r->c87 = Field::sub($this->c87, $other->c87);
        $r->c88 = Field::sub($this->c88, $other->c88);
        $r->c89 = Field::sub($this->c89, $other->c89);
        $r->c90 = Field::sub($this->c90, $other->c90);
        $r->c91 = Field::sub($this->c91, $other->c91);
        $r->c92 = Field::sub($this->c92, $other->c92);
        $r->c93 = Field::sub($this->c93, $other->c93);
        $r->c94 = Field::sub($this->c94, $other->c94);
        $r->c95 = Field::sub($this->c95, $other->c95);
        $r->c96 = Field::sub($this->c96, $other->c96);
        $r->c97 = Field::sub($this->c97, $other->c97);
        $r->c98 = Field::sub($this->c98, $other->c98);
        $r->c99 = Field::sub($this->c99, $other->c99);
        $r->c100 = Field::sub($this->c100, $other->c100);
        $r->c101 = Field::sub($this->c101, $other->c101);
        $r->c102 = Field::sub($this->c102, $other->c102);
        $r->c103 = Field::sub($this->c103, $other->c103);
        $r->c104 = Field::sub($this->c104, $other->c104);
        $r->c105 = Field::sub($this->c105, $other->c105);
        $r->c106 = Field::sub($this->c106, $other->c106);
        $r->c107 = Field::sub($this->c107, $other->c107);
        $r->c108 = Field::sub($this->c108, $other->c108);
        $r->c109 = Field::sub($this->c109, $other->c109);
        $r->c110 = Field::sub($this->c110, $other->c110);
        $r->c111 = Field::sub($this->c111, $other->c111);
        $r->c112 = Field::sub($this->c112, $other->c112);
        $r->c113 = Field::sub($this->c113, $other->c113);
        $r->c114 = Field::sub($this->c114, $other->c114);
        $r->c115 = Field::sub($this->c115, $other->c115);
        $r->c116 = Field::sub($this->c116, $other->c116);
        $r->c117 = Field::sub($this->c117, $other->c117);
        $r->c118 = Field::sub($this->c118, $other->c118);
        $r->c119 = Field::sub($this->c119, $other->c119);
        $r->c120 = Field::sub($this->c120, $other->c120);
        $r->c121 = Field::sub($this->c121, $other->c121);
        $r->c122 = Field::sub($this->c122, $other->c122);
        $r->c123 = Field::sub($this->c123, $other->c123);
        $r->c124 = Field::sub($this->c124, $other->c124);
        $r->c125 = Field::sub($this->c125, $other->c125);
        $r->c126 = Field::sub($this->c126, $other->c126);
        $r->c127 = Field::sub($this->c127, $other->c127);
        $r->c128 = Field::sub($this->c128, $other->c128);
        $r->c129 = Field::sub($this->c129, $other->c129);
        $r->c130 = Field::sub($this->c130, $other->c130);
        $r->c131 = Field::sub($this->c131, $other->c131);
        $r->c132 = Field::sub($this->c132, $other->c132);
        $r->c133 = Field::sub($this->c133, $other->c133);
        $r->c134 = Field::sub($this->c134, $other->c134);
        $r->c135 = Field::sub($this->c135, $other->c135);
        $r->c136 = Field::sub($this->c136, $other->c136);
        $r->c137 = Field::sub($this->c137, $other->c137);
        $r->c138 = Field::sub($this->c138, $other->c138);
        $r->c139 = Field::sub($this->c139, $other->c139);
        $r->c140 = Field::sub($this->c140, $other->c140);
        $r->c141 = Field::sub($this->c141, $other->c141);
        $r->c142 = Field::sub($this->c142, $other->c142);
        $r->c143 = Field::sub($this->c143, $other->c143);
        $r->c144 = Field::sub($this->c144, $other->c144);
        $r->c145 = Field::sub($this->c145, $other->c145);
        $r->c146 = Field::sub($this->c146, $other->c146);
        $r->c147 = Field::sub($this->c147, $other->c147);
        $r->c148 = Field::sub($this->c148, $other->c148);
        $r->c149 = Field::sub($this->c149, $other->c149);
        $r->c150 = Field::sub($this->c150, $other->c150);
        $r->c151 = Field::sub($this->c151, $other->c151);
        $r->c152 = Field::sub($this->c152, $other->c152);
        $r->c153 = Field::sub($this->c153, $other->c153);
        $r->c154 = Field::sub($this->c154, $other->c154);
        $r->c155 = Field::sub($this->c155, $other->c155);
        $r->c156 = Field::sub($this->c156, $other->c156);
        $r->c157 = Field::sub($this->c157, $other->c157);
        $r->c158 = Field::sub($this->c158, $other->c158);
        $r->c159 = Field::sub($this->c159, $other->c159);
        $r->c160 = Field::sub($this->c160, $other->c160);
        $r->c161 = Field::sub($this->c161, $other->c161);
        $r->c162 = Field::sub($this->c162, $other->c162);
        $r->c163 = Field::sub($this->c163, $other->c163);
        $r->c164 = Field::sub($this->c164, $other->c164);
        $r->c165 = Field::sub($this->c165, $other->c165);
        $r->c166 = Field::sub($this->c166, $other->c166);
        $r->c167 = Field::sub($this->c167, $other->c167);
        $r->c168 = Field::sub($this->c168, $other->c168);
        $r->c169 = Field::sub($this->c169, $other->c169);
        $r->c170 = Field::sub($this->c170, $other->c170);
        $r->c171 = Field::sub($this->c171, $other->c171);
        $r->c172 = Field::sub($this->c172, $other->c172);
        $r->c173 = Field::sub($this->c173, $other->c173);
        $r->c174 = Field::sub($this->c174, $other->c174);
        $r->c175 = Field::sub($this->c175, $other->c175);
        $r->c176 = Field::sub($this->c176, $other->c176);
        $r->c177 = Field::sub($this->c177, $other->c177);
        $r->c178 = Field::sub($this->c178, $other->c178);
        $r->c179 = Field::sub($this->c179, $other->c179);
        $r->c180 = Field::sub($this->c180, $other->c180);
        $r->c181 = Field::sub($this->c181, $other->c181);
        $r->c182 = Field::sub($this->c182, $other->c182);
        $r->c183 = Field::sub($this->c183, $other->c183);
        $r->c184 = Field::sub($this->c184, $other->c184);
        $r->c185 = Field::sub($this->c185, $other->c185);
        $r->c186 = Field::sub($this->c186, $other->c186);
        $r->c187 = Field::sub($this->c187, $other->c187);
        $r->c188 = Field::sub($this->c188, $other->c188);
        $r->c189 = Field::sub($this->c189, $other->c189);
        $r->c190 = Field::sub($this->c190, $other->c190);
        $r->c191 = Field::sub($this->c191, $other->c191);
        $r->c192 = Field::sub($this->c192, $other->c192);
        $r->c193 = Field::sub($this->c193, $other->c193);
        $r->c194 = Field::sub($this->c194, $other->c194);
        $r->c195 = Field::sub($this->c195, $other->c195);
        $r->c196 = Field::sub($this->c196, $other->c196);
        $r->c197 = Field::sub($this->c197, $other->c197);
        $r->c198 = Field::sub($this->c198, $other->c198);
        $r->c199 = Field::sub($this->c199, $other->c199);
        $r->c200 = Field::sub($this->c200, $other->c200);
        $r->c201 = Field::sub($this->c201, $other->c201);
        $r->c202 = Field::sub($this->c202, $other->c202);
        $r->c203 = Field::sub($this->c203, $other->c203);
        $r->c204 = Field::sub($this->c204, $other->c204);
        $r->c205 = Field::sub($this->c205, $other->c205);
        $r->c206 = Field::sub($this->c206, $other->c206);
        $r->c207 = Field::sub($this->c207, $other->c207);
        $r->c208 = Field::sub($this->c208, $other->c208);
        $r->c209 = Field::sub($this->c209, $other->c209);
        $r->c210 = Field::sub($this->c210, $other->c210);
        $r->c211 = Field::sub($this->c211, $other->c211);
        $r->c212 = Field::sub($this->c212, $other->c212);
        $r->c213 = Field::sub($this->c213, $other->c213);
        $r->c214 = Field::sub($this->c214, $other->c214);
        $r->c215 = Field::sub($this->c215, $other->c215);
        $r->c216 = Field::sub($this->c216, $other->c216);
        $r->c217 = Field::sub($this->c217, $other->c217);
        $r->c218 = Field::sub($this->c218, $other->c218);
        $r->c219 = Field::sub($this->c219, $other->c219);
        $r->c220 = Field::sub($this->c220, $other->c220);
        $r->c221 = Field::sub($this->c221, $other->c221);
        $r->c222 = Field::sub($this->c222, $other->c222);
        $r->c223 = Field::sub($this->c223, $other->c223);
        $r->c224 = Field::sub($this->c224, $other->c224);
        $r->c225 = Field::sub($this->c225, $other->c225);
        $r->c226 = Field::sub($this->c226, $other->c226);
        $r->c227 = Field::sub($this->c227, $other->c227);
        $r->c228 = Field::sub($this->c228, $other->c228);
        $r->c229 = Field::sub($this->c229, $other->c229);
        $r->c230 = Field::sub($this->c230, $other->c230);
        $r->c231 = Field::sub($this->c231, $other->c231);
        $r->c232 = Field::sub($this->c232, $other->c232);
        $r->c233 = Field::sub($this->c233, $other->c233);
        $r->c234 = Field::sub($this->c234, $other->c234);
        $r->c235 = Field::sub($this->c235, $other->c235);
        $r->c236 = Field::sub($this->c236, $other->c236);
        $r->c237 = Field::sub($this->c237, $other->c237);
        $r->c238 = Field::sub($this->c238, $other->c238);
        $r->c239 = Field::sub($this->c239, $other->c239);
        $r->c240 = Field::sub($this->c240, $other->c240);
        $r->c241 = Field::sub($this->c241, $other->c241);
        $r->c242 = Field::sub($this->c242, $other->c242);
        $r->c243 = Field::sub($this->c243, $other->c243);
        $r->c244 = Field::sub($this->c244, $other->c244);
        $r->c245 = Field::sub($this->c245, $other->c245);
        $r->c246 = Field::sub($this->c246, $other->c246);
        $r->c247 = Field::sub($this->c247, $other->c247);
        $r->c248 = Field::sub($this->c248, $other->c248);
        $r->c249 = Field::sub($this->c249, $other->c249);
        $r->c250 = Field::sub($this->c250, $other->c250);
        $r->c251 = Field::sub($this->c251, $other->c251);
        $r->c252 = Field::sub($this->c252, $other->c252);
        $r->c253 = Field::sub($this->c253, $other->c253);
        $r->c254 = Field::sub($this->c254, $other->c254);
        $r->c255 = Field::sub($this->c255, $other->c255);
        return $r;
    }

    public function negate(): Ring
    {
        $r = new Ring();
        $r->c0 = Field::neg($this->c0);
        $r->c1 = Field::neg($this->c1);
        $r->c2 = Field::neg($this->c2);
        $r->c3 = Field::neg($this->c3);
        $r->c4 = Field::neg($this->c4);
        $r->c5 = Field::neg($this->c5);
        $r->c6 = Field::neg($this->c6);
        $r->c7 = Field::neg($this->c7);
        $r->c8 = Field::neg($this->c8);
        $r->c9 = Field::neg($this->c9);
        $r->c10 = Field::neg($this->c10);
        $r->c11 = Field::neg($this->c11);
        $r->c12 = Field::neg($this->c12);
        $r->c13 = Field::neg($this->c13);
        $r->c14 = Field::neg($this->c14);
        $r->c15 = Field::neg($this->c15);
        $r->c16 = Field::neg($this->c16);
        $r->c17 = Field::neg($this->c17);
        $r->c18 = Field::neg($this->c18);
        $r->c19 = Field::neg($this->c19);
        $r->c20 = Field::neg($this->c20);
        $r->c21 = Field::neg($this->c21);
        $r->c22 = Field::neg($this->c22);
        $r->c23 = Field::neg($this->c23);
        $r->c24 = Field::neg($this->c24);
        $r->c25 = Field::neg($this->c25);
        $r->c26 = Field::neg($this->c26);
        $r->c27 = Field::neg($this->c27);
        $r->c28 = Field::neg($this->c28);
        $r->c29 = Field::neg($this->c29);
        $r->c30 = Field::neg($this->c30);
        $r->c31 = Field::neg($this->c31);
        $r->c32 = Field::neg($this->c32);
        $r->c33 = Field::neg($this->c33);
        $r->c34 = Field::neg($this->c34);
        $r->c35 = Field::neg($this->c35);
        $r->c36 = Field::neg($this->c36);
        $r->c37 = Field::neg($this->c37);
        $r->c38 = Field::neg($this->c38);
        $r->c39 = Field::neg($this->c39);
        $r->c40 = Field::neg($this->c40);
        $r->c41 = Field::neg($this->c41);
        $r->c42 = Field::neg($this->c42);
        $r->c43 = Field::neg($this->c43);
        $r->c44 = Field::neg($this->c44);
        $r->c45 = Field::neg($this->c45);
        $r->c46 = Field::neg($this->c46);
        $r->c47 = Field::neg($this->c47);
        $r->c48 = Field::neg($this->c48);
        $r->c49 = Field::neg($this->c49);
        $r->c50 = Field::neg($this->c50);
        $r->c51 = Field::neg($this->c51);
        $r->c52 = Field::neg($this->c52);
        $r->c53 = Field::neg($this->c53);
        $r->c54 = Field::neg($this->c54);
        $r->c55 = Field::neg($this->c55);
        $r->c56 = Field::neg($this->c56);
        $r->c57 = Field::neg($this->c57);
        $r->c58 = Field::neg($this->c58);
        $r->c59 = Field::neg($this->c59);
        $r->c60 = Field::neg($this->c60);
        $r->c61 = Field::neg($this->c61);
        $r->c62 = Field::neg($this->c62);
        $r->c63 = Field::neg($this->c63);
        $r->c64 = Field::neg($this->c64);
        $r->c65 = Field::neg($this->c65);
        $r->c66 = Field::neg($this->c66);
        $r->c67 = Field::neg($this->c67);
        $r->c68 = Field::neg($this->c68);
        $r->c69 = Field::neg($this->c69);
        $r->c70 = Field::neg($this->c70);
        $r->c71 = Field::neg($this->c71);
        $r->c72 = Field::neg($this->c72);
        $r->c73 = Field::neg($this->c73);
        $r->c74 = Field::neg($this->c74);
        $r->c75 = Field::neg($this->c75);
        $r->c76 = Field::neg($this->c76);
        $r->c77 = Field::neg($this->c77);
        $r->c78 = Field::neg($this->c78);
        $r->c79 = Field::neg($this->c79);
        $r->c80 = Field::neg($this->c80);
        $r->c81 = Field::neg($this->c81);
        $r->c82 = Field::neg($this->c82);
        $r->c83 = Field::neg($this->c83);
        $r->c84 = Field::neg($this->c84);
        $r->c85 = Field::neg($this->c85);
        $r->c86 = Field::neg($this->c86);
        $r->c87 = Field::neg($this->c87);
        $r->c88 = Field::neg($this->c88);
        $r->c89 = Field::neg($this->c89);
        $r->c90 = Field::neg($this->c90);
        $r->c91 = Field::neg($this->c91);
        $r->c92 = Field::neg($this->c92);
        $r->c93 = Field::neg($this->c93);
        $r->c94 = Field::neg($this->c94);
        $r->c95 = Field::neg($this->c95);
        $r->c96 = Field::neg($this->c96);
        $r->c97 = Field::neg($this->c97);
        $r->c98 = Field::neg($this->c98);
        $r->c99 = Field::neg($this->c99);
        $r->c100 = Field::neg($this->c100);
        $r->c101 = Field::neg($this->c101);
        $r->c102 = Field::neg($this->c102);
        $r->c103 = Field::neg($this->c103);
        $r->c104 = Field::neg($this->c104);
        $r->c105 = Field::neg($this->c105);
        $r->c106 = Field::neg($this->c106);
        $r->c107 = Field::neg($this->c107);
        $r->c108 = Field::neg($this->c108);
        $r->c109 = Field::neg($this->c109);
        $r->c110 = Field::neg($this->c110);
        $r->c111 = Field::neg($this->c111);
        $r->c112 = Field::neg($this->c112);
        $r->c113 = Field::neg($this->c113);
        $r->c114 = Field::neg($this->c114);
        $r->c115 = Field::neg($this->c115);
        $r->c116 = Field::neg($this->c116);
        $r->c117 = Field::neg($this->c117);
        $r->c118 = Field::neg($this->c118);
        $r->c119 = Field::neg($this->c119);
        $r->c120 = Field::neg($this->c120);
        $r->c121 = Field::neg($this->c121);
        $r->c122 = Field::neg($this->c122);
        $r->c123 = Field::neg($this->c123);
        $r->c124 = Field::neg($this->c124);
        $r->c125 = Field::neg($this->c125);
        $r->c126 = Field::neg($this->c126);
        $r->c127 = Field::neg($this->c127);
        $r->c128 = Field::neg($this->c128);
        $r->c129 = Field::neg($this->c129);
        $r->c130 = Field::neg($this->c130);
        $r->c131 = Field::neg($this->c131);
        $r->c132 = Field::neg($this->c132);
        $r->c133 = Field::neg($this->c133);
        $r->c134 = Field::neg($this->c134);
        $r->c135 = Field::neg($this->c135);
        $r->c136 = Field::neg($this->c136);
        $r->c137 = Field::neg($this->c137);
        $r->c138 = Field::neg($this->c138);
        $r->c139 = Field::neg($this->c139);
        $r->c140 = Field::neg($this->c140);
        $r->c141 = Field::neg($this->c141);
        $r->c142 = Field::neg($this->c142);
        $r->c143 = Field::neg($this->c143);
        $r->c144 = Field::neg($this->c144);
        $r->c145 = Field::neg($this->c145);
        $r->c146 = Field::neg($this->c146);
        $r->c147 = Field::neg($this->c147);
        $r->c148 = Field::neg($this->c148);
        $r->c149 = Field::neg($this->c149);
        $r->c150 = Field::neg($this->c150);
        $r->c151 = Field::neg($this->c151);
        $r->c152 = Field::neg($this->c152);
        $r->c153 = Field::neg($this->c153);
        $r->c154 = Field::neg($this->c154);
        $r->c155 = Field::neg($this->c155);
        $r->c156 = Field::neg($this->c156);
        $r->c157 = Field::neg($this->c157);
        $r->c158 = Field::neg($this->c158);
        $r->c159 = Field::neg($this->c159);
        $r->c160 = Field::neg($this->c160);
        $r->c161 = Field::neg($this->c161);
        $r->c162 = Field::neg($this->c162);
        $r->c163 = Field::neg($this->c163);
        $r->c164 = Field::neg($this->c164);
        $r->c165 = Field::neg($this->c165);
        $r->c166 = Field::neg($this->c166);
        $r->c167 = Field::neg($this->c167);
        $r->c168 = Field::neg($this->c168);
        $r->c169 = Field::neg($this->c169);
        $r->c170 = Field::neg($this->c170);
        $r->c171 = Field::neg($this->c171);
        $r->c172 = Field::neg($this->c172);
        $r->c173 = Field::neg($this->c173);
        $r->c174 = Field::neg($this->c174);
        $r->c175 = Field::neg($this->c175);
        $r->c176 = Field::neg($this->c176);
        $r->c177 = Field::neg($this->c177);
        $r->c178 = Field::neg($this->c178);
        $r->c179 = Field::neg($this->c179);
        $r->c180 = Field::neg($this->c180);
        $r->c181 = Field::neg($this->c181);
        $r->c182 = Field::neg($this->c182);
        $r->c183 = Field::neg($this->c183);
        $r->c184 = Field::neg($this->c184);
        $r->c185 = Field::neg($this->c185);
        $r->c186 = Field::neg($this->c186);
        $r->c187 = Field::neg($this->c187);
        $r->c188 = Field::neg($this->c188);
        $r->c189 = Field::neg($this->c189);
        $r->c190 = Field::neg($this->c190);
        $r->c191 = Field::neg($this->c191);
        $r->c192 = Field::neg($this->c192);
        $r->c193 = Field::neg($this->c193);
        $r->c194 = Field::neg($this->c194);
        $r->c195 = Field::neg($this->c195);
        $r->c196 = Field::neg($this->c196);
        $r->c197 = Field::neg($this->c197);
        $r->c198 = Field::neg($this->c198);
        $r->c199 = Field::neg($this->c199);
        $r->c200 = Field::neg($this->c200);
        $r->c201 = Field::neg($this->c201);
        $r->c202 = Field::neg($this->c202);
        $r->c203 = Field::neg($this->c203);
        $r->c204 = Field::neg($this->c204);
        $r->c205 = Field::neg($this->c205);
        $r->c206 = Field::neg($this->c206);
        $r->c207 = Field::neg($this->c207);
        $r->c208 = Field::neg($this->c208);
        $r->c209 = Field::neg($this->c209);
        $r->c210 = Field::neg($this->c210);
        $r->c211 = Field::neg($this->c211);
        $r->c212 = Field::neg($this->c212);
        $r->c213 = Field::neg($this->c213);
        $r->c214 = Field::neg($this->c214);
        $r->c215 = Field::neg($this->c215);
        $r->c216 = Field::neg($this->c216);
        $r->c217 = Field::neg($this->c217);
        $r->c218 = Field::neg($this->c218);
        $r->c219 = Field::neg($this->c219);
        $r->c220 = Field::neg($this->c220);
        $r->c221 = Field::neg($this->c221);
        $r->c222 = Field::neg($this->c222);
        $r->c223 = Field::neg($this->c223);
        $r->c224 = Field::neg($this->c224);
        $r->c225 = Field::neg($this->c225);
        $r->c226 = Field::neg($this->c226);
        $r->c227 = Field::neg($this->c227);
        $r->c228 = Field::neg($this->c228);
        $r->c229 = Field::neg($this->c229);
        $r->c230 = Field::neg($this->c230);
        $r->c231 = Field::neg($this->c231);
        $r->c232 = Field::neg($this->c232);
        $r->c233 = Field::neg($this->c233);
        $r->c234 = Field::neg($this->c234);
        $r->c235 = Field::neg($this->c235);
        $r->c236 = Field::neg($this->c236);
        $r->c237 = Field::neg($this->c237);
        $r->c238 = Field::neg($this->c238);
        $r->c239 = Field::neg($this->c239);
        $r->c240 = Field::neg($this->c240);
        $r->c241 = Field::neg($this->c241);
        $r->c242 = Field::neg($this->c242);
        $r->c243 = Field::neg($this->c243);
        $r->c244 = Field::neg($this->c244);
        $r->c245 = Field::neg($this->c245);
        $r->c246 = Field::neg($this->c246);
        $r->c247 = Field::neg($this->c247);
        $r->c248 = Field::neg($this->c248);
        $r->c249 = Field::neg($this->c249);
        $r->c250 = Field::neg($this->c250);
        $r->c251 = Field::neg($this->c251);
        $r->c252 = Field::neg($this->c252);
        $r->c253 = Field::neg($this->c253);
        $r->c254 = Field::neg($this->c254);
        $r->c255 = Field::neg($this->c255);
        return $r;
    }

    public function power2Round(): array
    {
        $r1 = new Ring();
        $r0 = new Ring();
        [$r1->c0, $r0->c0] = Field::power2round($this->c0);
        [$r1->c1, $r0->c1] = Field::power2round($this->c1);
        [$r1->c2, $r0->c2] = Field::power2round($this->c2);
        [$r1->c3, $r0->c3] = Field::power2round($this->c3);
        [$r1->c4, $r0->c4] = Field::power2round($this->c4);
        [$r1->c5, $r0->c5] = Field::power2round($this->c5);
        [$r1->c6, $r0->c6] = Field::power2round($this->c6);
        [$r1->c7, $r0->c7] = Field::power2round($this->c7);
        [$r1->c8, $r0->c8] = Field::power2round($this->c8);
        [$r1->c9, $r0->c9] = Field::power2round($this->c9);
        [$r1->c10, $r0->c10] = Field::power2round($this->c10);
        [$r1->c11, $r0->c11] = Field::power2round($this->c11);
        [$r1->c12, $r0->c12] = Field::power2round($this->c12);
        [$r1->c13, $r0->c13] = Field::power2round($this->c13);
        [$r1->c14, $r0->c14] = Field::power2round($this->c14);
        [$r1->c15, $r0->c15] = Field::power2round($this->c15);
        [$r1->c16, $r0->c16] = Field::power2round($this->c16);
        [$r1->c17, $r0->c17] = Field::power2round($this->c17);
        [$r1->c18, $r0->c18] = Field::power2round($this->c18);
        [$r1->c19, $r0->c19] = Field::power2round($this->c19);
        [$r1->c20, $r0->c20] = Field::power2round($this->c20);
        [$r1->c21, $r0->c21] = Field::power2round($this->c21);
        [$r1->c22, $r0->c22] = Field::power2round($this->c22);
        [$r1->c23, $r0->c23] = Field::power2round($this->c23);
        [$r1->c24, $r0->c24] = Field::power2round($this->c24);
        [$r1->c25, $r0->c25] = Field::power2round($this->c25);
        [$r1->c26, $r0->c26] = Field::power2round($this->c26);
        [$r1->c27, $r0->c27] = Field::power2round($this->c27);
        [$r1->c28, $r0->c28] = Field::power2round($this->c28);
        [$r1->c29, $r0->c29] = Field::power2round($this->c29);
        [$r1->c30, $r0->c30] = Field::power2round($this->c30);
        [$r1->c31, $r0->c31] = Field::power2round($this->c31);
        [$r1->c32, $r0->c32] = Field::power2round($this->c32);
        [$r1->c33, $r0->c33] = Field::power2round($this->c33);
        [$r1->c34, $r0->c34] = Field::power2round($this->c34);
        [$r1->c35, $r0->c35] = Field::power2round($this->c35);
        [$r1->c36, $r0->c36] = Field::power2round($this->c36);
        [$r1->c37, $r0->c37] = Field::power2round($this->c37);
        [$r1->c38, $r0->c38] = Field::power2round($this->c38);
        [$r1->c39, $r0->c39] = Field::power2round($this->c39);
        [$r1->c40, $r0->c40] = Field::power2round($this->c40);
        [$r1->c41, $r0->c41] = Field::power2round($this->c41);
        [$r1->c42, $r0->c42] = Field::power2round($this->c42);
        [$r1->c43, $r0->c43] = Field::power2round($this->c43);
        [$r1->c44, $r0->c44] = Field::power2round($this->c44);
        [$r1->c45, $r0->c45] = Field::power2round($this->c45);
        [$r1->c46, $r0->c46] = Field::power2round($this->c46);
        [$r1->c47, $r0->c47] = Field::power2round($this->c47);
        [$r1->c48, $r0->c48] = Field::power2round($this->c48);
        [$r1->c49, $r0->c49] = Field::power2round($this->c49);
        [$r1->c50, $r0->c50] = Field::power2round($this->c50);
        [$r1->c51, $r0->c51] = Field::power2round($this->c51);
        [$r1->c52, $r0->c52] = Field::power2round($this->c52);
        [$r1->c53, $r0->c53] = Field::power2round($this->c53);
        [$r1->c54, $r0->c54] = Field::power2round($this->c54);
        [$r1->c55, $r0->c55] = Field::power2round($this->c55);
        [$r1->c56, $r0->c56] = Field::power2round($this->c56);
        [$r1->c57, $r0->c57] = Field::power2round($this->c57);
        [$r1->c58, $r0->c58] = Field::power2round($this->c58);
        [$r1->c59, $r0->c59] = Field::power2round($this->c59);
        [$r1->c60, $r0->c60] = Field::power2round($this->c60);
        [$r1->c61, $r0->c61] = Field::power2round($this->c61);
        [$r1->c62, $r0->c62] = Field::power2round($this->c62);
        [$r1->c63, $r0->c63] = Field::power2round($this->c63);
        [$r1->c64, $r0->c64] = Field::power2round($this->c64);
        [$r1->c65, $r0->c65] = Field::power2round($this->c65);
        [$r1->c66, $r0->c66] = Field::power2round($this->c66);
        [$r1->c67, $r0->c67] = Field::power2round($this->c67);
        [$r1->c68, $r0->c68] = Field::power2round($this->c68);
        [$r1->c69, $r0->c69] = Field::power2round($this->c69);
        [$r1->c70, $r0->c70] = Field::power2round($this->c70);
        [$r1->c71, $r0->c71] = Field::power2round($this->c71);
        [$r1->c72, $r0->c72] = Field::power2round($this->c72);
        [$r1->c73, $r0->c73] = Field::power2round($this->c73);
        [$r1->c74, $r0->c74] = Field::power2round($this->c74);
        [$r1->c75, $r0->c75] = Field::power2round($this->c75);
        [$r1->c76, $r0->c76] = Field::power2round($this->c76);
        [$r1->c77, $r0->c77] = Field::power2round($this->c77);
        [$r1->c78, $r0->c78] = Field::power2round($this->c78);
        [$r1->c79, $r0->c79] = Field::power2round($this->c79);
        [$r1->c80, $r0->c80] = Field::power2round($this->c80);
        [$r1->c81, $r0->c81] = Field::power2round($this->c81);
        [$r1->c82, $r0->c82] = Field::power2round($this->c82);
        [$r1->c83, $r0->c83] = Field::power2round($this->c83);
        [$r1->c84, $r0->c84] = Field::power2round($this->c84);
        [$r1->c85, $r0->c85] = Field::power2round($this->c85);
        [$r1->c86, $r0->c86] = Field::power2round($this->c86);
        [$r1->c87, $r0->c87] = Field::power2round($this->c87);
        [$r1->c88, $r0->c88] = Field::power2round($this->c88);
        [$r1->c89, $r0->c89] = Field::power2round($this->c89);
        [$r1->c90, $r0->c90] = Field::power2round($this->c90);
        [$r1->c91, $r0->c91] = Field::power2round($this->c91);
        [$r1->c92, $r0->c92] = Field::power2round($this->c92);
        [$r1->c93, $r0->c93] = Field::power2round($this->c93);
        [$r1->c94, $r0->c94] = Field::power2round($this->c94);
        [$r1->c95, $r0->c95] = Field::power2round($this->c95);
        [$r1->c96, $r0->c96] = Field::power2round($this->c96);
        [$r1->c97, $r0->c97] = Field::power2round($this->c97);
        [$r1->c98, $r0->c98] = Field::power2round($this->c98);
        [$r1->c99, $r0->c99] = Field::power2round($this->c99);
        [$r1->c100, $r0->c100] = Field::power2round($this->c100);
        [$r1->c101, $r0->c101] = Field::power2round($this->c101);
        [$r1->c102, $r0->c102] = Field::power2round($this->c102);
        [$r1->c103, $r0->c103] = Field::power2round($this->c103);
        [$r1->c104, $r0->c104] = Field::power2round($this->c104);
        [$r1->c105, $r0->c105] = Field::power2round($this->c105);
        [$r1->c106, $r0->c106] = Field::power2round($this->c106);
        [$r1->c107, $r0->c107] = Field::power2round($this->c107);
        [$r1->c108, $r0->c108] = Field::power2round($this->c108);
        [$r1->c109, $r0->c109] = Field::power2round($this->c109);
        [$r1->c110, $r0->c110] = Field::power2round($this->c110);
        [$r1->c111, $r0->c111] = Field::power2round($this->c111);
        [$r1->c112, $r0->c112] = Field::power2round($this->c112);
        [$r1->c113, $r0->c113] = Field::power2round($this->c113);
        [$r1->c114, $r0->c114] = Field::power2round($this->c114);
        [$r1->c115, $r0->c115] = Field::power2round($this->c115);
        [$r1->c116, $r0->c116] = Field::power2round($this->c116);
        [$r1->c117, $r0->c117] = Field::power2round($this->c117);
        [$r1->c118, $r0->c118] = Field::power2round($this->c118);
        [$r1->c119, $r0->c119] = Field::power2round($this->c119);
        [$r1->c120, $r0->c120] = Field::power2round($this->c120);
        [$r1->c121, $r0->c121] = Field::power2round($this->c121);
        [$r1->c122, $r0->c122] = Field::power2round($this->c122);
        [$r1->c123, $r0->c123] = Field::power2round($this->c123);
        [$r1->c124, $r0->c124] = Field::power2round($this->c124);
        [$r1->c125, $r0->c125] = Field::power2round($this->c125);
        [$r1->c126, $r0->c126] = Field::power2round($this->c126);
        [$r1->c127, $r0->c127] = Field::power2round($this->c127);
        [$r1->c128, $r0->c128] = Field::power2round($this->c128);
        [$r1->c129, $r0->c129] = Field::power2round($this->c129);
        [$r1->c130, $r0->c130] = Field::power2round($this->c130);
        [$r1->c131, $r0->c131] = Field::power2round($this->c131);
        [$r1->c132, $r0->c132] = Field::power2round($this->c132);
        [$r1->c133, $r0->c133] = Field::power2round($this->c133);
        [$r1->c134, $r0->c134] = Field::power2round($this->c134);
        [$r1->c135, $r0->c135] = Field::power2round($this->c135);
        [$r1->c136, $r0->c136] = Field::power2round($this->c136);
        [$r1->c137, $r0->c137] = Field::power2round($this->c137);
        [$r1->c138, $r0->c138] = Field::power2round($this->c138);
        [$r1->c139, $r0->c139] = Field::power2round($this->c139);
        [$r1->c140, $r0->c140] = Field::power2round($this->c140);
        [$r1->c141, $r0->c141] = Field::power2round($this->c141);
        [$r1->c142, $r0->c142] = Field::power2round($this->c142);
        [$r1->c143, $r0->c143] = Field::power2round($this->c143);
        [$r1->c144, $r0->c144] = Field::power2round($this->c144);
        [$r1->c145, $r0->c145] = Field::power2round($this->c145);
        [$r1->c146, $r0->c146] = Field::power2round($this->c146);
        [$r1->c147, $r0->c147] = Field::power2round($this->c147);
        [$r1->c148, $r0->c148] = Field::power2round($this->c148);
        [$r1->c149, $r0->c149] = Field::power2round($this->c149);
        [$r1->c150, $r0->c150] = Field::power2round($this->c150);
        [$r1->c151, $r0->c151] = Field::power2round($this->c151);
        [$r1->c152, $r0->c152] = Field::power2round($this->c152);
        [$r1->c153, $r0->c153] = Field::power2round($this->c153);
        [$r1->c154, $r0->c154] = Field::power2round($this->c154);
        [$r1->c155, $r0->c155] = Field::power2round($this->c155);
        [$r1->c156, $r0->c156] = Field::power2round($this->c156);
        [$r1->c157, $r0->c157] = Field::power2round($this->c157);
        [$r1->c158, $r0->c158] = Field::power2round($this->c158);
        [$r1->c159, $r0->c159] = Field::power2round($this->c159);
        [$r1->c160, $r0->c160] = Field::power2round($this->c160);
        [$r1->c161, $r0->c161] = Field::power2round($this->c161);
        [$r1->c162, $r0->c162] = Field::power2round($this->c162);
        [$r1->c163, $r0->c163] = Field::power2round($this->c163);
        [$r1->c164, $r0->c164] = Field::power2round($this->c164);
        [$r1->c165, $r0->c165] = Field::power2round($this->c165);
        [$r1->c166, $r0->c166] = Field::power2round($this->c166);
        [$r1->c167, $r0->c167] = Field::power2round($this->c167);
        [$r1->c168, $r0->c168] = Field::power2round($this->c168);
        [$r1->c169, $r0->c169] = Field::power2round($this->c169);
        [$r1->c170, $r0->c170] = Field::power2round($this->c170);
        [$r1->c171, $r0->c171] = Field::power2round($this->c171);
        [$r1->c172, $r0->c172] = Field::power2round($this->c172);
        [$r1->c173, $r0->c173] = Field::power2round($this->c173);
        [$r1->c174, $r0->c174] = Field::power2round($this->c174);
        [$r1->c175, $r0->c175] = Field::power2round($this->c175);
        [$r1->c176, $r0->c176] = Field::power2round($this->c176);
        [$r1->c177, $r0->c177] = Field::power2round($this->c177);
        [$r1->c178, $r0->c178] = Field::power2round($this->c178);
        [$r1->c179, $r0->c179] = Field::power2round($this->c179);
        [$r1->c180, $r0->c180] = Field::power2round($this->c180);
        [$r1->c181, $r0->c181] = Field::power2round($this->c181);
        [$r1->c182, $r0->c182] = Field::power2round($this->c182);
        [$r1->c183, $r0->c183] = Field::power2round($this->c183);
        [$r1->c184, $r0->c184] = Field::power2round($this->c184);
        [$r1->c185, $r0->c185] = Field::power2round($this->c185);
        [$r1->c186, $r0->c186] = Field::power2round($this->c186);
        [$r1->c187, $r0->c187] = Field::power2round($this->c187);
        [$r1->c188, $r0->c188] = Field::power2round($this->c188);
        [$r1->c189, $r0->c189] = Field::power2round($this->c189);
        [$r1->c190, $r0->c190] = Field::power2round($this->c190);
        [$r1->c191, $r0->c191] = Field::power2round($this->c191);
        [$r1->c192, $r0->c192] = Field::power2round($this->c192);
        [$r1->c193, $r0->c193] = Field::power2round($this->c193);
        [$r1->c194, $r0->c194] = Field::power2round($this->c194);
        [$r1->c195, $r0->c195] = Field::power2round($this->c195);
        [$r1->c196, $r0->c196] = Field::power2round($this->c196);
        [$r1->c197, $r0->c197] = Field::power2round($this->c197);
        [$r1->c198, $r0->c198] = Field::power2round($this->c198);
        [$r1->c199, $r0->c199] = Field::power2round($this->c199);
        [$r1->c200, $r0->c200] = Field::power2round($this->c200);
        [$r1->c201, $r0->c201] = Field::power2round($this->c201);
        [$r1->c202, $r0->c202] = Field::power2round($this->c202);
        [$r1->c203, $r0->c203] = Field::power2round($this->c203);
        [$r1->c204, $r0->c204] = Field::power2round($this->c204);
        [$r1->c205, $r0->c205] = Field::power2round($this->c205);
        [$r1->c206, $r0->c206] = Field::power2round($this->c206);
        [$r1->c207, $r0->c207] = Field::power2round($this->c207);
        [$r1->c208, $r0->c208] = Field::power2round($this->c208);
        [$r1->c209, $r0->c209] = Field::power2round($this->c209);
        [$r1->c210, $r0->c210] = Field::power2round($this->c210);
        [$r1->c211, $r0->c211] = Field::power2round($this->c211);
        [$r1->c212, $r0->c212] = Field::power2round($this->c212);
        [$r1->c213, $r0->c213] = Field::power2round($this->c213);
        [$r1->c214, $r0->c214] = Field::power2round($this->c214);
        [$r1->c215, $r0->c215] = Field::power2round($this->c215);
        [$r1->c216, $r0->c216] = Field::power2round($this->c216);
        [$r1->c217, $r0->c217] = Field::power2round($this->c217);
        [$r1->c218, $r0->c218] = Field::power2round($this->c218);
        [$r1->c219, $r0->c219] = Field::power2round($this->c219);
        [$r1->c220, $r0->c220] = Field::power2round($this->c220);
        [$r1->c221, $r0->c221] = Field::power2round($this->c221);
        [$r1->c222, $r0->c222] = Field::power2round($this->c222);
        [$r1->c223, $r0->c223] = Field::power2round($this->c223);
        [$r1->c224, $r0->c224] = Field::power2round($this->c224);
        [$r1->c225, $r0->c225] = Field::power2round($this->c225);
        [$r1->c226, $r0->c226] = Field::power2round($this->c226);
        [$r1->c227, $r0->c227] = Field::power2round($this->c227);
        [$r1->c228, $r0->c228] = Field::power2round($this->c228);
        [$r1->c229, $r0->c229] = Field::power2round($this->c229);
        [$r1->c230, $r0->c230] = Field::power2round($this->c230);
        [$r1->c231, $r0->c231] = Field::power2round($this->c231);
        [$r1->c232, $r0->c232] = Field::power2round($this->c232);
        [$r1->c233, $r0->c233] = Field::power2round($this->c233);
        [$r1->c234, $r0->c234] = Field::power2round($this->c234);
        [$r1->c235, $r0->c235] = Field::power2round($this->c235);
        [$r1->c236, $r0->c236] = Field::power2round($this->c236);
        [$r1->c237, $r0->c237] = Field::power2round($this->c237);
        [$r1->c238, $r0->c238] = Field::power2round($this->c238);
        [$r1->c239, $r0->c239] = Field::power2round($this->c239);
        [$r1->c240, $r0->c240] = Field::power2round($this->c240);
        [$r1->c241, $r0->c241] = Field::power2round($this->c241);
        [$r1->c242, $r0->c242] = Field::power2round($this->c242);
        [$r1->c243, $r0->c243] = Field::power2round($this->c243);
        [$r1->c244, $r0->c244] = Field::power2round($this->c244);
        [$r1->c245, $r0->c245] = Field::power2round($this->c245);
        [$r1->c246, $r0->c246] = Field::power2round($this->c246);
        [$r1->c247, $r0->c247] = Field::power2round($this->c247);
        [$r1->c248, $r0->c248] = Field::power2round($this->c248);
        [$r1->c249, $r0->c249] = Field::power2round($this->c249);
        [$r1->c250, $r0->c250] = Field::power2round($this->c250);
        [$r1->c251, $r0->c251] = Field::power2round($this->c251);
        [$r1->c252, $r0->c252] = Field::power2round($this->c252);
        [$r1->c253, $r0->c253] = Field::power2round($this->c253);
        [$r1->c254, $r0->c254] = Field::power2round($this->c254);
        [$r1->c255, $r0->c255] = Field::power2round($this->c255);
        return [$r1, $r0];
    }

    /**
     * @throws MLDSAInternalException
     */
    public function highBits(Params $params): Ring
    {
        $r = new Ring();
        $g2 = $params->gamma2();
        $r->c0 = Field::highBits($this->c0, $g2);
        $r->c1 = Field::highBits($this->c1, $g2);
        $r->c2 = Field::highBits($this->c2, $g2);
        $r->c3 = Field::highBits($this->c3, $g2);
        $r->c4 = Field::highBits($this->c4, $g2);
        $r->c5 = Field::highBits($this->c5, $g2);
        $r->c6 = Field::highBits($this->c6, $g2);
        $r->c7 = Field::highBits($this->c7, $g2);
        $r->c8 = Field::highBits($this->c8, $g2);
        $r->c9 = Field::highBits($this->c9, $g2);
        $r->c10 = Field::highBits($this->c10, $g2);
        $r->c11 = Field::highBits($this->c11, $g2);
        $r->c12 = Field::highBits($this->c12, $g2);
        $r->c13 = Field::highBits($this->c13, $g2);
        $r->c14 = Field::highBits($this->c14, $g2);
        $r->c15 = Field::highBits($this->c15, $g2);
        $r->c16 = Field::highBits($this->c16, $g2);
        $r->c17 = Field::highBits($this->c17, $g2);
        $r->c18 = Field::highBits($this->c18, $g2);
        $r->c19 = Field::highBits($this->c19, $g2);
        $r->c20 = Field::highBits($this->c20, $g2);
        $r->c21 = Field::highBits($this->c21, $g2);
        $r->c22 = Field::highBits($this->c22, $g2);
        $r->c23 = Field::highBits($this->c23, $g2);
        $r->c24 = Field::highBits($this->c24, $g2);
        $r->c25 = Field::highBits($this->c25, $g2);
        $r->c26 = Field::highBits($this->c26, $g2);
        $r->c27 = Field::highBits($this->c27, $g2);
        $r->c28 = Field::highBits($this->c28, $g2);
        $r->c29 = Field::highBits($this->c29, $g2);
        $r->c30 = Field::highBits($this->c30, $g2);
        $r->c31 = Field::highBits($this->c31, $g2);
        $r->c32 = Field::highBits($this->c32, $g2);
        $r->c33 = Field::highBits($this->c33, $g2);
        $r->c34 = Field::highBits($this->c34, $g2);
        $r->c35 = Field::highBits($this->c35, $g2);
        $r->c36 = Field::highBits($this->c36, $g2);
        $r->c37 = Field::highBits($this->c37, $g2);
        $r->c38 = Field::highBits($this->c38, $g2);
        $r->c39 = Field::highBits($this->c39, $g2);
        $r->c40 = Field::highBits($this->c40, $g2);
        $r->c41 = Field::highBits($this->c41, $g2);
        $r->c42 = Field::highBits($this->c42, $g2);
        $r->c43 = Field::highBits($this->c43, $g2);
        $r->c44 = Field::highBits($this->c44, $g2);
        $r->c45 = Field::highBits($this->c45, $g2);
        $r->c46 = Field::highBits($this->c46, $g2);
        $r->c47 = Field::highBits($this->c47, $g2);
        $r->c48 = Field::highBits($this->c48, $g2);
        $r->c49 = Field::highBits($this->c49, $g2);
        $r->c50 = Field::highBits($this->c50, $g2);
        $r->c51 = Field::highBits($this->c51, $g2);
        $r->c52 = Field::highBits($this->c52, $g2);
        $r->c53 = Field::highBits($this->c53, $g2);
        $r->c54 = Field::highBits($this->c54, $g2);
        $r->c55 = Field::highBits($this->c55, $g2);
        $r->c56 = Field::highBits($this->c56, $g2);
        $r->c57 = Field::highBits($this->c57, $g2);
        $r->c58 = Field::highBits($this->c58, $g2);
        $r->c59 = Field::highBits($this->c59, $g2);
        $r->c60 = Field::highBits($this->c60, $g2);
        $r->c61 = Field::highBits($this->c61, $g2);
        $r->c62 = Field::highBits($this->c62, $g2);
        $r->c63 = Field::highBits($this->c63, $g2);
        $r->c64 = Field::highBits($this->c64, $g2);
        $r->c65 = Field::highBits($this->c65, $g2);
        $r->c66 = Field::highBits($this->c66, $g2);
        $r->c67 = Field::highBits($this->c67, $g2);
        $r->c68 = Field::highBits($this->c68, $g2);
        $r->c69 = Field::highBits($this->c69, $g2);
        $r->c70 = Field::highBits($this->c70, $g2);
        $r->c71 = Field::highBits($this->c71, $g2);
        $r->c72 = Field::highBits($this->c72, $g2);
        $r->c73 = Field::highBits($this->c73, $g2);
        $r->c74 = Field::highBits($this->c74, $g2);
        $r->c75 = Field::highBits($this->c75, $g2);
        $r->c76 = Field::highBits($this->c76, $g2);
        $r->c77 = Field::highBits($this->c77, $g2);
        $r->c78 = Field::highBits($this->c78, $g2);
        $r->c79 = Field::highBits($this->c79, $g2);
        $r->c80 = Field::highBits($this->c80, $g2);
        $r->c81 = Field::highBits($this->c81, $g2);
        $r->c82 = Field::highBits($this->c82, $g2);
        $r->c83 = Field::highBits($this->c83, $g2);
        $r->c84 = Field::highBits($this->c84, $g2);
        $r->c85 = Field::highBits($this->c85, $g2);
        $r->c86 = Field::highBits($this->c86, $g2);
        $r->c87 = Field::highBits($this->c87, $g2);
        $r->c88 = Field::highBits($this->c88, $g2);
        $r->c89 = Field::highBits($this->c89, $g2);
        $r->c90 = Field::highBits($this->c90, $g2);
        $r->c91 = Field::highBits($this->c91, $g2);
        $r->c92 = Field::highBits($this->c92, $g2);
        $r->c93 = Field::highBits($this->c93, $g2);
        $r->c94 = Field::highBits($this->c94, $g2);
        $r->c95 = Field::highBits($this->c95, $g2);
        $r->c96 = Field::highBits($this->c96, $g2);
        $r->c97 = Field::highBits($this->c97, $g2);
        $r->c98 = Field::highBits($this->c98, $g2);
        $r->c99 = Field::highBits($this->c99, $g2);
        $r->c100 = Field::highBits($this->c100, $g2);
        $r->c101 = Field::highBits($this->c101, $g2);
        $r->c102 = Field::highBits($this->c102, $g2);
        $r->c103 = Field::highBits($this->c103, $g2);
        $r->c104 = Field::highBits($this->c104, $g2);
        $r->c105 = Field::highBits($this->c105, $g2);
        $r->c106 = Field::highBits($this->c106, $g2);
        $r->c107 = Field::highBits($this->c107, $g2);
        $r->c108 = Field::highBits($this->c108, $g2);
        $r->c109 = Field::highBits($this->c109, $g2);
        $r->c110 = Field::highBits($this->c110, $g2);
        $r->c111 = Field::highBits($this->c111, $g2);
        $r->c112 = Field::highBits($this->c112, $g2);
        $r->c113 = Field::highBits($this->c113, $g2);
        $r->c114 = Field::highBits($this->c114, $g2);
        $r->c115 = Field::highBits($this->c115, $g2);
        $r->c116 = Field::highBits($this->c116, $g2);
        $r->c117 = Field::highBits($this->c117, $g2);
        $r->c118 = Field::highBits($this->c118, $g2);
        $r->c119 = Field::highBits($this->c119, $g2);
        $r->c120 = Field::highBits($this->c120, $g2);
        $r->c121 = Field::highBits($this->c121, $g2);
        $r->c122 = Field::highBits($this->c122, $g2);
        $r->c123 = Field::highBits($this->c123, $g2);
        $r->c124 = Field::highBits($this->c124, $g2);
        $r->c125 = Field::highBits($this->c125, $g2);
        $r->c126 = Field::highBits($this->c126, $g2);
        $r->c127 = Field::highBits($this->c127, $g2);
        $r->c128 = Field::highBits($this->c128, $g2);
        $r->c129 = Field::highBits($this->c129, $g2);
        $r->c130 = Field::highBits($this->c130, $g2);
        $r->c131 = Field::highBits($this->c131, $g2);
        $r->c132 = Field::highBits($this->c132, $g2);
        $r->c133 = Field::highBits($this->c133, $g2);
        $r->c134 = Field::highBits($this->c134, $g2);
        $r->c135 = Field::highBits($this->c135, $g2);
        $r->c136 = Field::highBits($this->c136, $g2);
        $r->c137 = Field::highBits($this->c137, $g2);
        $r->c138 = Field::highBits($this->c138, $g2);
        $r->c139 = Field::highBits($this->c139, $g2);
        $r->c140 = Field::highBits($this->c140, $g2);
        $r->c141 = Field::highBits($this->c141, $g2);
        $r->c142 = Field::highBits($this->c142, $g2);
        $r->c143 = Field::highBits($this->c143, $g2);
        $r->c144 = Field::highBits($this->c144, $g2);
        $r->c145 = Field::highBits($this->c145, $g2);
        $r->c146 = Field::highBits($this->c146, $g2);
        $r->c147 = Field::highBits($this->c147, $g2);
        $r->c148 = Field::highBits($this->c148, $g2);
        $r->c149 = Field::highBits($this->c149, $g2);
        $r->c150 = Field::highBits($this->c150, $g2);
        $r->c151 = Field::highBits($this->c151, $g2);
        $r->c152 = Field::highBits($this->c152, $g2);
        $r->c153 = Field::highBits($this->c153, $g2);
        $r->c154 = Field::highBits($this->c154, $g2);
        $r->c155 = Field::highBits($this->c155, $g2);
        $r->c156 = Field::highBits($this->c156, $g2);
        $r->c157 = Field::highBits($this->c157, $g2);
        $r->c158 = Field::highBits($this->c158, $g2);
        $r->c159 = Field::highBits($this->c159, $g2);
        $r->c160 = Field::highBits($this->c160, $g2);
        $r->c161 = Field::highBits($this->c161, $g2);
        $r->c162 = Field::highBits($this->c162, $g2);
        $r->c163 = Field::highBits($this->c163, $g2);
        $r->c164 = Field::highBits($this->c164, $g2);
        $r->c165 = Field::highBits($this->c165, $g2);
        $r->c166 = Field::highBits($this->c166, $g2);
        $r->c167 = Field::highBits($this->c167, $g2);
        $r->c168 = Field::highBits($this->c168, $g2);
        $r->c169 = Field::highBits($this->c169, $g2);
        $r->c170 = Field::highBits($this->c170, $g2);
        $r->c171 = Field::highBits($this->c171, $g2);
        $r->c172 = Field::highBits($this->c172, $g2);
        $r->c173 = Field::highBits($this->c173, $g2);
        $r->c174 = Field::highBits($this->c174, $g2);
        $r->c175 = Field::highBits($this->c175, $g2);
        $r->c176 = Field::highBits($this->c176, $g2);
        $r->c177 = Field::highBits($this->c177, $g2);
        $r->c178 = Field::highBits($this->c178, $g2);
        $r->c179 = Field::highBits($this->c179, $g2);
        $r->c180 = Field::highBits($this->c180, $g2);
        $r->c181 = Field::highBits($this->c181, $g2);
        $r->c182 = Field::highBits($this->c182, $g2);
        $r->c183 = Field::highBits($this->c183, $g2);
        $r->c184 = Field::highBits($this->c184, $g2);
        $r->c185 = Field::highBits($this->c185, $g2);
        $r->c186 = Field::highBits($this->c186, $g2);
        $r->c187 = Field::highBits($this->c187, $g2);
        $r->c188 = Field::highBits($this->c188, $g2);
        $r->c189 = Field::highBits($this->c189, $g2);
        $r->c190 = Field::highBits($this->c190, $g2);
        $r->c191 = Field::highBits($this->c191, $g2);
        $r->c192 = Field::highBits($this->c192, $g2);
        $r->c193 = Field::highBits($this->c193, $g2);
        $r->c194 = Field::highBits($this->c194, $g2);
        $r->c195 = Field::highBits($this->c195, $g2);
        $r->c196 = Field::highBits($this->c196, $g2);
        $r->c197 = Field::highBits($this->c197, $g2);
        $r->c198 = Field::highBits($this->c198, $g2);
        $r->c199 = Field::highBits($this->c199, $g2);
        $r->c200 = Field::highBits($this->c200, $g2);
        $r->c201 = Field::highBits($this->c201, $g2);
        $r->c202 = Field::highBits($this->c202, $g2);
        $r->c203 = Field::highBits($this->c203, $g2);
        $r->c204 = Field::highBits($this->c204, $g2);
        $r->c205 = Field::highBits($this->c205, $g2);
        $r->c206 = Field::highBits($this->c206, $g2);
        $r->c207 = Field::highBits($this->c207, $g2);
        $r->c208 = Field::highBits($this->c208, $g2);
        $r->c209 = Field::highBits($this->c209, $g2);
        $r->c210 = Field::highBits($this->c210, $g2);
        $r->c211 = Field::highBits($this->c211, $g2);
        $r->c212 = Field::highBits($this->c212, $g2);
        $r->c213 = Field::highBits($this->c213, $g2);
        $r->c214 = Field::highBits($this->c214, $g2);
        $r->c215 = Field::highBits($this->c215, $g2);
        $r->c216 = Field::highBits($this->c216, $g2);
        $r->c217 = Field::highBits($this->c217, $g2);
        $r->c218 = Field::highBits($this->c218, $g2);
        $r->c219 = Field::highBits($this->c219, $g2);
        $r->c220 = Field::highBits($this->c220, $g2);
        $r->c221 = Field::highBits($this->c221, $g2);
        $r->c222 = Field::highBits($this->c222, $g2);
        $r->c223 = Field::highBits($this->c223, $g2);
        $r->c224 = Field::highBits($this->c224, $g2);
        $r->c225 = Field::highBits($this->c225, $g2);
        $r->c226 = Field::highBits($this->c226, $g2);
        $r->c227 = Field::highBits($this->c227, $g2);
        $r->c228 = Field::highBits($this->c228, $g2);
        $r->c229 = Field::highBits($this->c229, $g2);
        $r->c230 = Field::highBits($this->c230, $g2);
        $r->c231 = Field::highBits($this->c231, $g2);
        $r->c232 = Field::highBits($this->c232, $g2);
        $r->c233 = Field::highBits($this->c233, $g2);
        $r->c234 = Field::highBits($this->c234, $g2);
        $r->c235 = Field::highBits($this->c235, $g2);
        $r->c236 = Field::highBits($this->c236, $g2);
        $r->c237 = Field::highBits($this->c237, $g2);
        $r->c238 = Field::highBits($this->c238, $g2);
        $r->c239 = Field::highBits($this->c239, $g2);
        $r->c240 = Field::highBits($this->c240, $g2);
        $r->c241 = Field::highBits($this->c241, $g2);
        $r->c242 = Field::highBits($this->c242, $g2);
        $r->c243 = Field::highBits($this->c243, $g2);
        $r->c244 = Field::highBits($this->c244, $g2);
        $r->c245 = Field::highBits($this->c245, $g2);
        $r->c246 = Field::highBits($this->c246, $g2);
        $r->c247 = Field::highBits($this->c247, $g2);
        $r->c248 = Field::highBits($this->c248, $g2);
        $r->c249 = Field::highBits($this->c249, $g2);
        $r->c250 = Field::highBits($this->c250, $g2);
        $r->c251 = Field::highBits($this->c251, $g2);
        $r->c252 = Field::highBits($this->c252, $g2);
        $r->c253 = Field::highBits($this->c253, $g2);
        $r->c254 = Field::highBits($this->c254, $g2);
        $r->c255 = Field::highBits($this->c255, $g2);
        return $r;
    }

    /**
     * @throws MLDSAInternalException
     */
    public function lowBits(Params $params): Ring
    {
        $r = new Ring();
        $g2 = $params->gamma2();
        $r->c0 = Field::lowBits($this->c0, $g2);
        $r->c1 = Field::lowBits($this->c1, $g2);
        $r->c2 = Field::lowBits($this->c2, $g2);
        $r->c3 = Field::lowBits($this->c3, $g2);
        $r->c4 = Field::lowBits($this->c4, $g2);
        $r->c5 = Field::lowBits($this->c5, $g2);
        $r->c6 = Field::lowBits($this->c6, $g2);
        $r->c7 = Field::lowBits($this->c7, $g2);
        $r->c8 = Field::lowBits($this->c8, $g2);
        $r->c9 = Field::lowBits($this->c9, $g2);
        $r->c10 = Field::lowBits($this->c10, $g2);
        $r->c11 = Field::lowBits($this->c11, $g2);
        $r->c12 = Field::lowBits($this->c12, $g2);
        $r->c13 = Field::lowBits($this->c13, $g2);
        $r->c14 = Field::lowBits($this->c14, $g2);
        $r->c15 = Field::lowBits($this->c15, $g2);
        $r->c16 = Field::lowBits($this->c16, $g2);
        $r->c17 = Field::lowBits($this->c17, $g2);
        $r->c18 = Field::lowBits($this->c18, $g2);
        $r->c19 = Field::lowBits($this->c19, $g2);
        $r->c20 = Field::lowBits($this->c20, $g2);
        $r->c21 = Field::lowBits($this->c21, $g2);
        $r->c22 = Field::lowBits($this->c22, $g2);
        $r->c23 = Field::lowBits($this->c23, $g2);
        $r->c24 = Field::lowBits($this->c24, $g2);
        $r->c25 = Field::lowBits($this->c25, $g2);
        $r->c26 = Field::lowBits($this->c26, $g2);
        $r->c27 = Field::lowBits($this->c27, $g2);
        $r->c28 = Field::lowBits($this->c28, $g2);
        $r->c29 = Field::lowBits($this->c29, $g2);
        $r->c30 = Field::lowBits($this->c30, $g2);
        $r->c31 = Field::lowBits($this->c31, $g2);
        $r->c32 = Field::lowBits($this->c32, $g2);
        $r->c33 = Field::lowBits($this->c33, $g2);
        $r->c34 = Field::lowBits($this->c34, $g2);
        $r->c35 = Field::lowBits($this->c35, $g2);
        $r->c36 = Field::lowBits($this->c36, $g2);
        $r->c37 = Field::lowBits($this->c37, $g2);
        $r->c38 = Field::lowBits($this->c38, $g2);
        $r->c39 = Field::lowBits($this->c39, $g2);
        $r->c40 = Field::lowBits($this->c40, $g2);
        $r->c41 = Field::lowBits($this->c41, $g2);
        $r->c42 = Field::lowBits($this->c42, $g2);
        $r->c43 = Field::lowBits($this->c43, $g2);
        $r->c44 = Field::lowBits($this->c44, $g2);
        $r->c45 = Field::lowBits($this->c45, $g2);
        $r->c46 = Field::lowBits($this->c46, $g2);
        $r->c47 = Field::lowBits($this->c47, $g2);
        $r->c48 = Field::lowBits($this->c48, $g2);
        $r->c49 = Field::lowBits($this->c49, $g2);
        $r->c50 = Field::lowBits($this->c50, $g2);
        $r->c51 = Field::lowBits($this->c51, $g2);
        $r->c52 = Field::lowBits($this->c52, $g2);
        $r->c53 = Field::lowBits($this->c53, $g2);
        $r->c54 = Field::lowBits($this->c54, $g2);
        $r->c55 = Field::lowBits($this->c55, $g2);
        $r->c56 = Field::lowBits($this->c56, $g2);
        $r->c57 = Field::lowBits($this->c57, $g2);
        $r->c58 = Field::lowBits($this->c58, $g2);
        $r->c59 = Field::lowBits($this->c59, $g2);
        $r->c60 = Field::lowBits($this->c60, $g2);
        $r->c61 = Field::lowBits($this->c61, $g2);
        $r->c62 = Field::lowBits($this->c62, $g2);
        $r->c63 = Field::lowBits($this->c63, $g2);
        $r->c64 = Field::lowBits($this->c64, $g2);
        $r->c65 = Field::lowBits($this->c65, $g2);
        $r->c66 = Field::lowBits($this->c66, $g2);
        $r->c67 = Field::lowBits($this->c67, $g2);
        $r->c68 = Field::lowBits($this->c68, $g2);
        $r->c69 = Field::lowBits($this->c69, $g2);
        $r->c70 = Field::lowBits($this->c70, $g2);
        $r->c71 = Field::lowBits($this->c71, $g2);
        $r->c72 = Field::lowBits($this->c72, $g2);
        $r->c73 = Field::lowBits($this->c73, $g2);
        $r->c74 = Field::lowBits($this->c74, $g2);
        $r->c75 = Field::lowBits($this->c75, $g2);
        $r->c76 = Field::lowBits($this->c76, $g2);
        $r->c77 = Field::lowBits($this->c77, $g2);
        $r->c78 = Field::lowBits($this->c78, $g2);
        $r->c79 = Field::lowBits($this->c79, $g2);
        $r->c80 = Field::lowBits($this->c80, $g2);
        $r->c81 = Field::lowBits($this->c81, $g2);
        $r->c82 = Field::lowBits($this->c82, $g2);
        $r->c83 = Field::lowBits($this->c83, $g2);
        $r->c84 = Field::lowBits($this->c84, $g2);
        $r->c85 = Field::lowBits($this->c85, $g2);
        $r->c86 = Field::lowBits($this->c86, $g2);
        $r->c87 = Field::lowBits($this->c87, $g2);
        $r->c88 = Field::lowBits($this->c88, $g2);
        $r->c89 = Field::lowBits($this->c89, $g2);
        $r->c90 = Field::lowBits($this->c90, $g2);
        $r->c91 = Field::lowBits($this->c91, $g2);
        $r->c92 = Field::lowBits($this->c92, $g2);
        $r->c93 = Field::lowBits($this->c93, $g2);
        $r->c94 = Field::lowBits($this->c94, $g2);
        $r->c95 = Field::lowBits($this->c95, $g2);
        $r->c96 = Field::lowBits($this->c96, $g2);
        $r->c97 = Field::lowBits($this->c97, $g2);
        $r->c98 = Field::lowBits($this->c98, $g2);
        $r->c99 = Field::lowBits($this->c99, $g2);
        $r->c100 = Field::lowBits($this->c100, $g2);
        $r->c101 = Field::lowBits($this->c101, $g2);
        $r->c102 = Field::lowBits($this->c102, $g2);
        $r->c103 = Field::lowBits($this->c103, $g2);
        $r->c104 = Field::lowBits($this->c104, $g2);
        $r->c105 = Field::lowBits($this->c105, $g2);
        $r->c106 = Field::lowBits($this->c106, $g2);
        $r->c107 = Field::lowBits($this->c107, $g2);
        $r->c108 = Field::lowBits($this->c108, $g2);
        $r->c109 = Field::lowBits($this->c109, $g2);
        $r->c110 = Field::lowBits($this->c110, $g2);
        $r->c111 = Field::lowBits($this->c111, $g2);
        $r->c112 = Field::lowBits($this->c112, $g2);
        $r->c113 = Field::lowBits($this->c113, $g2);
        $r->c114 = Field::lowBits($this->c114, $g2);
        $r->c115 = Field::lowBits($this->c115, $g2);
        $r->c116 = Field::lowBits($this->c116, $g2);
        $r->c117 = Field::lowBits($this->c117, $g2);
        $r->c118 = Field::lowBits($this->c118, $g2);
        $r->c119 = Field::lowBits($this->c119, $g2);
        $r->c120 = Field::lowBits($this->c120, $g2);
        $r->c121 = Field::lowBits($this->c121, $g2);
        $r->c122 = Field::lowBits($this->c122, $g2);
        $r->c123 = Field::lowBits($this->c123, $g2);
        $r->c124 = Field::lowBits($this->c124, $g2);
        $r->c125 = Field::lowBits($this->c125, $g2);
        $r->c126 = Field::lowBits($this->c126, $g2);
        $r->c127 = Field::lowBits($this->c127, $g2);
        $r->c128 = Field::lowBits($this->c128, $g2);
        $r->c129 = Field::lowBits($this->c129, $g2);
        $r->c130 = Field::lowBits($this->c130, $g2);
        $r->c131 = Field::lowBits($this->c131, $g2);
        $r->c132 = Field::lowBits($this->c132, $g2);
        $r->c133 = Field::lowBits($this->c133, $g2);
        $r->c134 = Field::lowBits($this->c134, $g2);
        $r->c135 = Field::lowBits($this->c135, $g2);
        $r->c136 = Field::lowBits($this->c136, $g2);
        $r->c137 = Field::lowBits($this->c137, $g2);
        $r->c138 = Field::lowBits($this->c138, $g2);
        $r->c139 = Field::lowBits($this->c139, $g2);
        $r->c140 = Field::lowBits($this->c140, $g2);
        $r->c141 = Field::lowBits($this->c141, $g2);
        $r->c142 = Field::lowBits($this->c142, $g2);
        $r->c143 = Field::lowBits($this->c143, $g2);
        $r->c144 = Field::lowBits($this->c144, $g2);
        $r->c145 = Field::lowBits($this->c145, $g2);
        $r->c146 = Field::lowBits($this->c146, $g2);
        $r->c147 = Field::lowBits($this->c147, $g2);
        $r->c148 = Field::lowBits($this->c148, $g2);
        $r->c149 = Field::lowBits($this->c149, $g2);
        $r->c150 = Field::lowBits($this->c150, $g2);
        $r->c151 = Field::lowBits($this->c151, $g2);
        $r->c152 = Field::lowBits($this->c152, $g2);
        $r->c153 = Field::lowBits($this->c153, $g2);
        $r->c154 = Field::lowBits($this->c154, $g2);
        $r->c155 = Field::lowBits($this->c155, $g2);
        $r->c156 = Field::lowBits($this->c156, $g2);
        $r->c157 = Field::lowBits($this->c157, $g2);
        $r->c158 = Field::lowBits($this->c158, $g2);
        $r->c159 = Field::lowBits($this->c159, $g2);
        $r->c160 = Field::lowBits($this->c160, $g2);
        $r->c161 = Field::lowBits($this->c161, $g2);
        $r->c162 = Field::lowBits($this->c162, $g2);
        $r->c163 = Field::lowBits($this->c163, $g2);
        $r->c164 = Field::lowBits($this->c164, $g2);
        $r->c165 = Field::lowBits($this->c165, $g2);
        $r->c166 = Field::lowBits($this->c166, $g2);
        $r->c167 = Field::lowBits($this->c167, $g2);
        $r->c168 = Field::lowBits($this->c168, $g2);
        $r->c169 = Field::lowBits($this->c169, $g2);
        $r->c170 = Field::lowBits($this->c170, $g2);
        $r->c171 = Field::lowBits($this->c171, $g2);
        $r->c172 = Field::lowBits($this->c172, $g2);
        $r->c173 = Field::lowBits($this->c173, $g2);
        $r->c174 = Field::lowBits($this->c174, $g2);
        $r->c175 = Field::lowBits($this->c175, $g2);
        $r->c176 = Field::lowBits($this->c176, $g2);
        $r->c177 = Field::lowBits($this->c177, $g2);
        $r->c178 = Field::lowBits($this->c178, $g2);
        $r->c179 = Field::lowBits($this->c179, $g2);
        $r->c180 = Field::lowBits($this->c180, $g2);
        $r->c181 = Field::lowBits($this->c181, $g2);
        $r->c182 = Field::lowBits($this->c182, $g2);
        $r->c183 = Field::lowBits($this->c183, $g2);
        $r->c184 = Field::lowBits($this->c184, $g2);
        $r->c185 = Field::lowBits($this->c185, $g2);
        $r->c186 = Field::lowBits($this->c186, $g2);
        $r->c187 = Field::lowBits($this->c187, $g2);
        $r->c188 = Field::lowBits($this->c188, $g2);
        $r->c189 = Field::lowBits($this->c189, $g2);
        $r->c190 = Field::lowBits($this->c190, $g2);
        $r->c191 = Field::lowBits($this->c191, $g2);
        $r->c192 = Field::lowBits($this->c192, $g2);
        $r->c193 = Field::lowBits($this->c193, $g2);
        $r->c194 = Field::lowBits($this->c194, $g2);
        $r->c195 = Field::lowBits($this->c195, $g2);
        $r->c196 = Field::lowBits($this->c196, $g2);
        $r->c197 = Field::lowBits($this->c197, $g2);
        $r->c198 = Field::lowBits($this->c198, $g2);
        $r->c199 = Field::lowBits($this->c199, $g2);
        $r->c200 = Field::lowBits($this->c200, $g2);
        $r->c201 = Field::lowBits($this->c201, $g2);
        $r->c202 = Field::lowBits($this->c202, $g2);
        $r->c203 = Field::lowBits($this->c203, $g2);
        $r->c204 = Field::lowBits($this->c204, $g2);
        $r->c205 = Field::lowBits($this->c205, $g2);
        $r->c206 = Field::lowBits($this->c206, $g2);
        $r->c207 = Field::lowBits($this->c207, $g2);
        $r->c208 = Field::lowBits($this->c208, $g2);
        $r->c209 = Field::lowBits($this->c209, $g2);
        $r->c210 = Field::lowBits($this->c210, $g2);
        $r->c211 = Field::lowBits($this->c211, $g2);
        $r->c212 = Field::lowBits($this->c212, $g2);
        $r->c213 = Field::lowBits($this->c213, $g2);
        $r->c214 = Field::lowBits($this->c214, $g2);
        $r->c215 = Field::lowBits($this->c215, $g2);
        $r->c216 = Field::lowBits($this->c216, $g2);
        $r->c217 = Field::lowBits($this->c217, $g2);
        $r->c218 = Field::lowBits($this->c218, $g2);
        $r->c219 = Field::lowBits($this->c219, $g2);
        $r->c220 = Field::lowBits($this->c220, $g2);
        $r->c221 = Field::lowBits($this->c221, $g2);
        $r->c222 = Field::lowBits($this->c222, $g2);
        $r->c223 = Field::lowBits($this->c223, $g2);
        $r->c224 = Field::lowBits($this->c224, $g2);
        $r->c225 = Field::lowBits($this->c225, $g2);
        $r->c226 = Field::lowBits($this->c226, $g2);
        $r->c227 = Field::lowBits($this->c227, $g2);
        $r->c228 = Field::lowBits($this->c228, $g2);
        $r->c229 = Field::lowBits($this->c229, $g2);
        $r->c230 = Field::lowBits($this->c230, $g2);
        $r->c231 = Field::lowBits($this->c231, $g2);
        $r->c232 = Field::lowBits($this->c232, $g2);
        $r->c233 = Field::lowBits($this->c233, $g2);
        $r->c234 = Field::lowBits($this->c234, $g2);
        $r->c235 = Field::lowBits($this->c235, $g2);
        $r->c236 = Field::lowBits($this->c236, $g2);
        $r->c237 = Field::lowBits($this->c237, $g2);
        $r->c238 = Field::lowBits($this->c238, $g2);
        $r->c239 = Field::lowBits($this->c239, $g2);
        $r->c240 = Field::lowBits($this->c240, $g2);
        $r->c241 = Field::lowBits($this->c241, $g2);
        $r->c242 = Field::lowBits($this->c242, $g2);
        $r->c243 = Field::lowBits($this->c243, $g2);
        $r->c244 = Field::lowBits($this->c244, $g2);
        $r->c245 = Field::lowBits($this->c245, $g2);
        $r->c246 = Field::lowBits($this->c246, $g2);
        $r->c247 = Field::lowBits($this->c247, $g2);
        $r->c248 = Field::lowBits($this->c248, $g2);
        $r->c249 = Field::lowBits($this->c249, $g2);
        $r->c250 = Field::lowBits($this->c250, $g2);
        $r->c251 = Field::lowBits($this->c251, $g2);
        $r->c252 = Field::lowBits($this->c252, $g2);
        $r->c253 = Field::lowBits($this->c253, $g2);
        $r->c254 = Field::lowBits($this->c254, $g2);
        $r->c255 = Field::lowBits($this->c255, $g2);
        return $r;
    }

    public function infinityNorm(): int
    {
        return max(
            Field::infinityNorm($this->c0),
            Field::infinityNorm($this->c1),
            Field::infinityNorm($this->c2),
            Field::infinityNorm($this->c3),
            Field::infinityNorm($this->c4),
            Field::infinityNorm($this->c5),
            Field::infinityNorm($this->c6),
            Field::infinityNorm($this->c7),
            Field::infinityNorm($this->c8),
            Field::infinityNorm($this->c9),
            Field::infinityNorm($this->c10),
            Field::infinityNorm($this->c11),
            Field::infinityNorm($this->c12),
            Field::infinityNorm($this->c13),
            Field::infinityNorm($this->c14),
            Field::infinityNorm($this->c15),
            Field::infinityNorm($this->c16),
            Field::infinityNorm($this->c17),
            Field::infinityNorm($this->c18),
            Field::infinityNorm($this->c19),
            Field::infinityNorm($this->c20),
            Field::infinityNorm($this->c21),
            Field::infinityNorm($this->c22),
            Field::infinityNorm($this->c23),
            Field::infinityNorm($this->c24),
            Field::infinityNorm($this->c25),
            Field::infinityNorm($this->c26),
            Field::infinityNorm($this->c27),
            Field::infinityNorm($this->c28),
            Field::infinityNorm($this->c29),
            Field::infinityNorm($this->c30),
            Field::infinityNorm($this->c31),
            Field::infinityNorm($this->c32),
            Field::infinityNorm($this->c33),
            Field::infinityNorm($this->c34),
            Field::infinityNorm($this->c35),
            Field::infinityNorm($this->c36),
            Field::infinityNorm($this->c37),
            Field::infinityNorm($this->c38),
            Field::infinityNorm($this->c39),
            Field::infinityNorm($this->c40),
            Field::infinityNorm($this->c41),
            Field::infinityNorm($this->c42),
            Field::infinityNorm($this->c43),
            Field::infinityNorm($this->c44),
            Field::infinityNorm($this->c45),
            Field::infinityNorm($this->c46),
            Field::infinityNorm($this->c47),
            Field::infinityNorm($this->c48),
            Field::infinityNorm($this->c49),
            Field::infinityNorm($this->c50),
            Field::infinityNorm($this->c51),
            Field::infinityNorm($this->c52),
            Field::infinityNorm($this->c53),
            Field::infinityNorm($this->c54),
            Field::infinityNorm($this->c55),
            Field::infinityNorm($this->c56),
            Field::infinityNorm($this->c57),
            Field::infinityNorm($this->c58),
            Field::infinityNorm($this->c59),
            Field::infinityNorm($this->c60),
            Field::infinityNorm($this->c61),
            Field::infinityNorm($this->c62),
            Field::infinityNorm($this->c63),
            Field::infinityNorm($this->c64),
            Field::infinityNorm($this->c65),
            Field::infinityNorm($this->c66),
            Field::infinityNorm($this->c67),
            Field::infinityNorm($this->c68),
            Field::infinityNorm($this->c69),
            Field::infinityNorm($this->c70),
            Field::infinityNorm($this->c71),
            Field::infinityNorm($this->c72),
            Field::infinityNorm($this->c73),
            Field::infinityNorm($this->c74),
            Field::infinityNorm($this->c75),
            Field::infinityNorm($this->c76),
            Field::infinityNorm($this->c77),
            Field::infinityNorm($this->c78),
            Field::infinityNorm($this->c79),
            Field::infinityNorm($this->c80),
            Field::infinityNorm($this->c81),
            Field::infinityNorm($this->c82),
            Field::infinityNorm($this->c83),
            Field::infinityNorm($this->c84),
            Field::infinityNorm($this->c85),
            Field::infinityNorm($this->c86),
            Field::infinityNorm($this->c87),
            Field::infinityNorm($this->c88),
            Field::infinityNorm($this->c89),
            Field::infinityNorm($this->c90),
            Field::infinityNorm($this->c91),
            Field::infinityNorm($this->c92),
            Field::infinityNorm($this->c93),
            Field::infinityNorm($this->c94),
            Field::infinityNorm($this->c95),
            Field::infinityNorm($this->c96),
            Field::infinityNorm($this->c97),
            Field::infinityNorm($this->c98),
            Field::infinityNorm($this->c99),
            Field::infinityNorm($this->c100),
            Field::infinityNorm($this->c101),
            Field::infinityNorm($this->c102),
            Field::infinityNorm($this->c103),
            Field::infinityNorm($this->c104),
            Field::infinityNorm($this->c105),
            Field::infinityNorm($this->c106),
            Field::infinityNorm($this->c107),
            Field::infinityNorm($this->c108),
            Field::infinityNorm($this->c109),
            Field::infinityNorm($this->c110),
            Field::infinityNorm($this->c111),
            Field::infinityNorm($this->c112),
            Field::infinityNorm($this->c113),
            Field::infinityNorm($this->c114),
            Field::infinityNorm($this->c115),
            Field::infinityNorm($this->c116),
            Field::infinityNorm($this->c117),
            Field::infinityNorm($this->c118),
            Field::infinityNorm($this->c119),
            Field::infinityNorm($this->c120),
            Field::infinityNorm($this->c121),
            Field::infinityNorm($this->c122),
            Field::infinityNorm($this->c123),
            Field::infinityNorm($this->c124),
            Field::infinityNorm($this->c125),
            Field::infinityNorm($this->c126),
            Field::infinityNorm($this->c127),
            Field::infinityNorm($this->c128),
            Field::infinityNorm($this->c129),
            Field::infinityNorm($this->c130),
            Field::infinityNorm($this->c131),
            Field::infinityNorm($this->c132),
            Field::infinityNorm($this->c133),
            Field::infinityNorm($this->c134),
            Field::infinityNorm($this->c135),
            Field::infinityNorm($this->c136),
            Field::infinityNorm($this->c137),
            Field::infinityNorm($this->c138),
            Field::infinityNorm($this->c139),
            Field::infinityNorm($this->c140),
            Field::infinityNorm($this->c141),
            Field::infinityNorm($this->c142),
            Field::infinityNorm($this->c143),
            Field::infinityNorm($this->c144),
            Field::infinityNorm($this->c145),
            Field::infinityNorm($this->c146),
            Field::infinityNorm($this->c147),
            Field::infinityNorm($this->c148),
            Field::infinityNorm($this->c149),
            Field::infinityNorm($this->c150),
            Field::infinityNorm($this->c151),
            Field::infinityNorm($this->c152),
            Field::infinityNorm($this->c153),
            Field::infinityNorm($this->c154),
            Field::infinityNorm($this->c155),
            Field::infinityNorm($this->c156),
            Field::infinityNorm($this->c157),
            Field::infinityNorm($this->c158),
            Field::infinityNorm($this->c159),
            Field::infinityNorm($this->c160),
            Field::infinityNorm($this->c161),
            Field::infinityNorm($this->c162),
            Field::infinityNorm($this->c163),
            Field::infinityNorm($this->c164),
            Field::infinityNorm($this->c165),
            Field::infinityNorm($this->c166),
            Field::infinityNorm($this->c167),
            Field::infinityNorm($this->c168),
            Field::infinityNorm($this->c169),
            Field::infinityNorm($this->c170),
            Field::infinityNorm($this->c171),
            Field::infinityNorm($this->c172),
            Field::infinityNorm($this->c173),
            Field::infinityNorm($this->c174),
            Field::infinityNorm($this->c175),
            Field::infinityNorm($this->c176),
            Field::infinityNorm($this->c177),
            Field::infinityNorm($this->c178),
            Field::infinityNorm($this->c179),
            Field::infinityNorm($this->c180),
            Field::infinityNorm($this->c181),
            Field::infinityNorm($this->c182),
            Field::infinityNorm($this->c183),
            Field::infinityNorm($this->c184),
            Field::infinityNorm($this->c185),
            Field::infinityNorm($this->c186),
            Field::infinityNorm($this->c187),
            Field::infinityNorm($this->c188),
            Field::infinityNorm($this->c189),
            Field::infinityNorm($this->c190),
            Field::infinityNorm($this->c191),
            Field::infinityNorm($this->c192),
            Field::infinityNorm($this->c193),
            Field::infinityNorm($this->c194),
            Field::infinityNorm($this->c195),
            Field::infinityNorm($this->c196),
            Field::infinityNorm($this->c197),
            Field::infinityNorm($this->c198),
            Field::infinityNorm($this->c199),
            Field::infinityNorm($this->c200),
            Field::infinityNorm($this->c201),
            Field::infinityNorm($this->c202),
            Field::infinityNorm($this->c203),
            Field::infinityNorm($this->c204),
            Field::infinityNorm($this->c205),
            Field::infinityNorm($this->c206),
            Field::infinityNorm($this->c207),
            Field::infinityNorm($this->c208),
            Field::infinityNorm($this->c209),
            Field::infinityNorm($this->c210),
            Field::infinityNorm($this->c211),
            Field::infinityNorm($this->c212),
            Field::infinityNorm($this->c213),
            Field::infinityNorm($this->c214),
            Field::infinityNorm($this->c215),
            Field::infinityNorm($this->c216),
            Field::infinityNorm($this->c217),
            Field::infinityNorm($this->c218),
            Field::infinityNorm($this->c219),
            Field::infinityNorm($this->c220),
            Field::infinityNorm($this->c221),
            Field::infinityNorm($this->c222),
            Field::infinityNorm($this->c223),
            Field::infinityNorm($this->c224),
            Field::infinityNorm($this->c225),
            Field::infinityNorm($this->c226),
            Field::infinityNorm($this->c227),
            Field::infinityNorm($this->c228),
            Field::infinityNorm($this->c229),
            Field::infinityNorm($this->c230),
            Field::infinityNorm($this->c231),
            Field::infinityNorm($this->c232),
            Field::infinityNorm($this->c233),
            Field::infinityNorm($this->c234),
            Field::infinityNorm($this->c235),
            Field::infinityNorm($this->c236),
            Field::infinityNorm($this->c237),
            Field::infinityNorm($this->c238),
            Field::infinityNorm($this->c239),
            Field::infinityNorm($this->c240),
            Field::infinityNorm($this->c241),
            Field::infinityNorm($this->c242),
            Field::infinityNorm($this->c243),
            Field::infinityNorm($this->c244),
            Field::infinityNorm($this->c245),
            Field::infinityNorm($this->c246),
            Field::infinityNorm($this->c247),
            Field::infinityNorm($this->c248),
            Field::infinityNorm($this->c249),
            Field::infinityNorm($this->c250),
            Field::infinityNorm($this->c251),
            Field::infinityNorm($this->c252),
            Field::infinityNorm($this->c253),
            Field::infinityNorm($this->c254),
            Field::infinityNorm($this->c255)
        );
    }

    public function symmetric(): Ring
    {
        $r = new Ring();
        $r->c0 = Field::symmetric($this->c0);
        $r->c1 = Field::symmetric($this->c1);
        $r->c2 = Field::symmetric($this->c2);
        $r->c3 = Field::symmetric($this->c3);
        $r->c4 = Field::symmetric($this->c4);
        $r->c5 = Field::symmetric($this->c5);
        $r->c6 = Field::symmetric($this->c6);
        $r->c7 = Field::symmetric($this->c7);
        $r->c8 = Field::symmetric($this->c8);
        $r->c9 = Field::symmetric($this->c9);
        $r->c10 = Field::symmetric($this->c10);
        $r->c11 = Field::symmetric($this->c11);
        $r->c12 = Field::symmetric($this->c12);
        $r->c13 = Field::symmetric($this->c13);
        $r->c14 = Field::symmetric($this->c14);
        $r->c15 = Field::symmetric($this->c15);
        $r->c16 = Field::symmetric($this->c16);
        $r->c17 = Field::symmetric($this->c17);
        $r->c18 = Field::symmetric($this->c18);
        $r->c19 = Field::symmetric($this->c19);
        $r->c20 = Field::symmetric($this->c20);
        $r->c21 = Field::symmetric($this->c21);
        $r->c22 = Field::symmetric($this->c22);
        $r->c23 = Field::symmetric($this->c23);
        $r->c24 = Field::symmetric($this->c24);
        $r->c25 = Field::symmetric($this->c25);
        $r->c26 = Field::symmetric($this->c26);
        $r->c27 = Field::symmetric($this->c27);
        $r->c28 = Field::symmetric($this->c28);
        $r->c29 = Field::symmetric($this->c29);
        $r->c30 = Field::symmetric($this->c30);
        $r->c31 = Field::symmetric($this->c31);
        $r->c32 = Field::symmetric($this->c32);
        $r->c33 = Field::symmetric($this->c33);
        $r->c34 = Field::symmetric($this->c34);
        $r->c35 = Field::symmetric($this->c35);
        $r->c36 = Field::symmetric($this->c36);
        $r->c37 = Field::symmetric($this->c37);
        $r->c38 = Field::symmetric($this->c38);
        $r->c39 = Field::symmetric($this->c39);
        $r->c40 = Field::symmetric($this->c40);
        $r->c41 = Field::symmetric($this->c41);
        $r->c42 = Field::symmetric($this->c42);
        $r->c43 = Field::symmetric($this->c43);
        $r->c44 = Field::symmetric($this->c44);
        $r->c45 = Field::symmetric($this->c45);
        $r->c46 = Field::symmetric($this->c46);
        $r->c47 = Field::symmetric($this->c47);
        $r->c48 = Field::symmetric($this->c48);
        $r->c49 = Field::symmetric($this->c49);
        $r->c50 = Field::symmetric($this->c50);
        $r->c51 = Field::symmetric($this->c51);
        $r->c52 = Field::symmetric($this->c52);
        $r->c53 = Field::symmetric($this->c53);
        $r->c54 = Field::symmetric($this->c54);
        $r->c55 = Field::symmetric($this->c55);
        $r->c56 = Field::symmetric($this->c56);
        $r->c57 = Field::symmetric($this->c57);
        $r->c58 = Field::symmetric($this->c58);
        $r->c59 = Field::symmetric($this->c59);
        $r->c60 = Field::symmetric($this->c60);
        $r->c61 = Field::symmetric($this->c61);
        $r->c62 = Field::symmetric($this->c62);
        $r->c63 = Field::symmetric($this->c63);
        $r->c64 = Field::symmetric($this->c64);
        $r->c65 = Field::symmetric($this->c65);
        $r->c66 = Field::symmetric($this->c66);
        $r->c67 = Field::symmetric($this->c67);
        $r->c68 = Field::symmetric($this->c68);
        $r->c69 = Field::symmetric($this->c69);
        $r->c70 = Field::symmetric($this->c70);
        $r->c71 = Field::symmetric($this->c71);
        $r->c72 = Field::symmetric($this->c72);
        $r->c73 = Field::symmetric($this->c73);
        $r->c74 = Field::symmetric($this->c74);
        $r->c75 = Field::symmetric($this->c75);
        $r->c76 = Field::symmetric($this->c76);
        $r->c77 = Field::symmetric($this->c77);
        $r->c78 = Field::symmetric($this->c78);
        $r->c79 = Field::symmetric($this->c79);
        $r->c80 = Field::symmetric($this->c80);
        $r->c81 = Field::symmetric($this->c81);
        $r->c82 = Field::symmetric($this->c82);
        $r->c83 = Field::symmetric($this->c83);
        $r->c84 = Field::symmetric($this->c84);
        $r->c85 = Field::symmetric($this->c85);
        $r->c86 = Field::symmetric($this->c86);
        $r->c87 = Field::symmetric($this->c87);
        $r->c88 = Field::symmetric($this->c88);
        $r->c89 = Field::symmetric($this->c89);
        $r->c90 = Field::symmetric($this->c90);
        $r->c91 = Field::symmetric($this->c91);
        $r->c92 = Field::symmetric($this->c92);
        $r->c93 = Field::symmetric($this->c93);
        $r->c94 = Field::symmetric($this->c94);
        $r->c95 = Field::symmetric($this->c95);
        $r->c96 = Field::symmetric($this->c96);
        $r->c97 = Field::symmetric($this->c97);
        $r->c98 = Field::symmetric($this->c98);
        $r->c99 = Field::symmetric($this->c99);
        $r->c100 = Field::symmetric($this->c100);
        $r->c101 = Field::symmetric($this->c101);
        $r->c102 = Field::symmetric($this->c102);
        $r->c103 = Field::symmetric($this->c103);
        $r->c104 = Field::symmetric($this->c104);
        $r->c105 = Field::symmetric($this->c105);
        $r->c106 = Field::symmetric($this->c106);
        $r->c107 = Field::symmetric($this->c107);
        $r->c108 = Field::symmetric($this->c108);
        $r->c109 = Field::symmetric($this->c109);
        $r->c110 = Field::symmetric($this->c110);
        $r->c111 = Field::symmetric($this->c111);
        $r->c112 = Field::symmetric($this->c112);
        $r->c113 = Field::symmetric($this->c113);
        $r->c114 = Field::symmetric($this->c114);
        $r->c115 = Field::symmetric($this->c115);
        $r->c116 = Field::symmetric($this->c116);
        $r->c117 = Field::symmetric($this->c117);
        $r->c118 = Field::symmetric($this->c118);
        $r->c119 = Field::symmetric($this->c119);
        $r->c120 = Field::symmetric($this->c120);
        $r->c121 = Field::symmetric($this->c121);
        $r->c122 = Field::symmetric($this->c122);
        $r->c123 = Field::symmetric($this->c123);
        $r->c124 = Field::symmetric($this->c124);
        $r->c125 = Field::symmetric($this->c125);
        $r->c126 = Field::symmetric($this->c126);
        $r->c127 = Field::symmetric($this->c127);
        $r->c128 = Field::symmetric($this->c128);
        $r->c129 = Field::symmetric($this->c129);
        $r->c130 = Field::symmetric($this->c130);
        $r->c131 = Field::symmetric($this->c131);
        $r->c132 = Field::symmetric($this->c132);
        $r->c133 = Field::symmetric($this->c133);
        $r->c134 = Field::symmetric($this->c134);
        $r->c135 = Field::symmetric($this->c135);
        $r->c136 = Field::symmetric($this->c136);
        $r->c137 = Field::symmetric($this->c137);
        $r->c138 = Field::symmetric($this->c138);
        $r->c139 = Field::symmetric($this->c139);
        $r->c140 = Field::symmetric($this->c140);
        $r->c141 = Field::symmetric($this->c141);
        $r->c142 = Field::symmetric($this->c142);
        $r->c143 = Field::symmetric($this->c143);
        $r->c144 = Field::symmetric($this->c144);
        $r->c145 = Field::symmetric($this->c145);
        $r->c146 = Field::symmetric($this->c146);
        $r->c147 = Field::symmetric($this->c147);
        $r->c148 = Field::symmetric($this->c148);
        $r->c149 = Field::symmetric($this->c149);
        $r->c150 = Field::symmetric($this->c150);
        $r->c151 = Field::symmetric($this->c151);
        $r->c152 = Field::symmetric($this->c152);
        $r->c153 = Field::symmetric($this->c153);
        $r->c154 = Field::symmetric($this->c154);
        $r->c155 = Field::symmetric($this->c155);
        $r->c156 = Field::symmetric($this->c156);
        $r->c157 = Field::symmetric($this->c157);
        $r->c158 = Field::symmetric($this->c158);
        $r->c159 = Field::symmetric($this->c159);
        $r->c160 = Field::symmetric($this->c160);
        $r->c161 = Field::symmetric($this->c161);
        $r->c162 = Field::symmetric($this->c162);
        $r->c163 = Field::symmetric($this->c163);
        $r->c164 = Field::symmetric($this->c164);
        $r->c165 = Field::symmetric($this->c165);
        $r->c166 = Field::symmetric($this->c166);
        $r->c167 = Field::symmetric($this->c167);
        $r->c168 = Field::symmetric($this->c168);
        $r->c169 = Field::symmetric($this->c169);
        $r->c170 = Field::symmetric($this->c170);
        $r->c171 = Field::symmetric($this->c171);
        $r->c172 = Field::symmetric($this->c172);
        $r->c173 = Field::symmetric($this->c173);
        $r->c174 = Field::symmetric($this->c174);
        $r->c175 = Field::symmetric($this->c175);
        $r->c176 = Field::symmetric($this->c176);
        $r->c177 = Field::symmetric($this->c177);
        $r->c178 = Field::symmetric($this->c178);
        $r->c179 = Field::symmetric($this->c179);
        $r->c180 = Field::symmetric($this->c180);
        $r->c181 = Field::symmetric($this->c181);
        $r->c182 = Field::symmetric($this->c182);
        $r->c183 = Field::symmetric($this->c183);
        $r->c184 = Field::symmetric($this->c184);
        $r->c185 = Field::symmetric($this->c185);
        $r->c186 = Field::symmetric($this->c186);
        $r->c187 = Field::symmetric($this->c187);
        $r->c188 = Field::symmetric($this->c188);
        $r->c189 = Field::symmetric($this->c189);
        $r->c190 = Field::symmetric($this->c190);
        $r->c191 = Field::symmetric($this->c191);
        $r->c192 = Field::symmetric($this->c192);
        $r->c193 = Field::symmetric($this->c193);
        $r->c194 = Field::symmetric($this->c194);
        $r->c195 = Field::symmetric($this->c195);
        $r->c196 = Field::symmetric($this->c196);
        $r->c197 = Field::symmetric($this->c197);
        $r->c198 = Field::symmetric($this->c198);
        $r->c199 = Field::symmetric($this->c199);
        $r->c200 = Field::symmetric($this->c200);
        $r->c201 = Field::symmetric($this->c201);
        $r->c202 = Field::symmetric($this->c202);
        $r->c203 = Field::symmetric($this->c203);
        $r->c204 = Field::symmetric($this->c204);
        $r->c205 = Field::symmetric($this->c205);
        $r->c206 = Field::symmetric($this->c206);
        $r->c207 = Field::symmetric($this->c207);
        $r->c208 = Field::symmetric($this->c208);
        $r->c209 = Field::symmetric($this->c209);
        $r->c210 = Field::symmetric($this->c210);
        $r->c211 = Field::symmetric($this->c211);
        $r->c212 = Field::symmetric($this->c212);
        $r->c213 = Field::symmetric($this->c213);
        $r->c214 = Field::symmetric($this->c214);
        $r->c215 = Field::symmetric($this->c215);
        $r->c216 = Field::symmetric($this->c216);
        $r->c217 = Field::symmetric($this->c217);
        $r->c218 = Field::symmetric($this->c218);
        $r->c219 = Field::symmetric($this->c219);
        $r->c220 = Field::symmetric($this->c220);
        $r->c221 = Field::symmetric($this->c221);
        $r->c222 = Field::symmetric($this->c222);
        $r->c223 = Field::symmetric($this->c223);
        $r->c224 = Field::symmetric($this->c224);
        $r->c225 = Field::symmetric($this->c225);
        $r->c226 = Field::symmetric($this->c226);
        $r->c227 = Field::symmetric($this->c227);
        $r->c228 = Field::symmetric($this->c228);
        $r->c229 = Field::symmetric($this->c229);
        $r->c230 = Field::symmetric($this->c230);
        $r->c231 = Field::symmetric($this->c231);
        $r->c232 = Field::symmetric($this->c232);
        $r->c233 = Field::symmetric($this->c233);
        $r->c234 = Field::symmetric($this->c234);
        $r->c235 = Field::symmetric($this->c235);
        $r->c236 = Field::symmetric($this->c236);
        $r->c237 = Field::symmetric($this->c237);
        $r->c238 = Field::symmetric($this->c238);
        $r->c239 = Field::symmetric($this->c239);
        $r->c240 = Field::symmetric($this->c240);
        $r->c241 = Field::symmetric($this->c241);
        $r->c242 = Field::symmetric($this->c242);
        $r->c243 = Field::symmetric($this->c243);
        $r->c244 = Field::symmetric($this->c244);
        $r->c245 = Field::symmetric($this->c245);
        $r->c246 = Field::symmetric($this->c246);
        $r->c247 = Field::symmetric($this->c247);
        $r->c248 = Field::symmetric($this->c248);
        $r->c249 = Field::symmetric($this->c249);
        $r->c250 = Field::symmetric($this->c250);
        $r->c251 = Field::symmetric($this->c251);
        $r->c252 = Field::symmetric($this->c252);
        $r->c253 = Field::symmetric($this->c253);
        $r->c254 = Field::symmetric($this->c254);
        $r->c255 = Field::symmetric($this->c255);
        return $r;
    }

    public function scalarMul(int $c): Ring
    {
        $r = new Ring();
        $r->c0 = Field::mul($this->c0, $c);
        $r->c1 = Field::mul($this->c1, $c);
        $r->c2 = Field::mul($this->c2, $c);
        $r->c3 = Field::mul($this->c3, $c);
        $r->c4 = Field::mul($this->c4, $c);
        $r->c5 = Field::mul($this->c5, $c);
        $r->c6 = Field::mul($this->c6, $c);
        $r->c7 = Field::mul($this->c7, $c);
        $r->c8 = Field::mul($this->c8, $c);
        $r->c9 = Field::mul($this->c9, $c);
        $r->c10 = Field::mul($this->c10, $c);
        $r->c11 = Field::mul($this->c11, $c);
        $r->c12 = Field::mul($this->c12, $c);
        $r->c13 = Field::mul($this->c13, $c);
        $r->c14 = Field::mul($this->c14, $c);
        $r->c15 = Field::mul($this->c15, $c);
        $r->c16 = Field::mul($this->c16, $c);
        $r->c17 = Field::mul($this->c17, $c);
        $r->c18 = Field::mul($this->c18, $c);
        $r->c19 = Field::mul($this->c19, $c);
        $r->c20 = Field::mul($this->c20, $c);
        $r->c21 = Field::mul($this->c21, $c);
        $r->c22 = Field::mul($this->c22, $c);
        $r->c23 = Field::mul($this->c23, $c);
        $r->c24 = Field::mul($this->c24, $c);
        $r->c25 = Field::mul($this->c25, $c);
        $r->c26 = Field::mul($this->c26, $c);
        $r->c27 = Field::mul($this->c27, $c);
        $r->c28 = Field::mul($this->c28, $c);
        $r->c29 = Field::mul($this->c29, $c);
        $r->c30 = Field::mul($this->c30, $c);
        $r->c31 = Field::mul($this->c31, $c);
        $r->c32 = Field::mul($this->c32, $c);
        $r->c33 = Field::mul($this->c33, $c);
        $r->c34 = Field::mul($this->c34, $c);
        $r->c35 = Field::mul($this->c35, $c);
        $r->c36 = Field::mul($this->c36, $c);
        $r->c37 = Field::mul($this->c37, $c);
        $r->c38 = Field::mul($this->c38, $c);
        $r->c39 = Field::mul($this->c39, $c);
        $r->c40 = Field::mul($this->c40, $c);
        $r->c41 = Field::mul($this->c41, $c);
        $r->c42 = Field::mul($this->c42, $c);
        $r->c43 = Field::mul($this->c43, $c);
        $r->c44 = Field::mul($this->c44, $c);
        $r->c45 = Field::mul($this->c45, $c);
        $r->c46 = Field::mul($this->c46, $c);
        $r->c47 = Field::mul($this->c47, $c);
        $r->c48 = Field::mul($this->c48, $c);
        $r->c49 = Field::mul($this->c49, $c);
        $r->c50 = Field::mul($this->c50, $c);
        $r->c51 = Field::mul($this->c51, $c);
        $r->c52 = Field::mul($this->c52, $c);
        $r->c53 = Field::mul($this->c53, $c);
        $r->c54 = Field::mul($this->c54, $c);
        $r->c55 = Field::mul($this->c55, $c);
        $r->c56 = Field::mul($this->c56, $c);
        $r->c57 = Field::mul($this->c57, $c);
        $r->c58 = Field::mul($this->c58, $c);
        $r->c59 = Field::mul($this->c59, $c);
        $r->c60 = Field::mul($this->c60, $c);
        $r->c61 = Field::mul($this->c61, $c);
        $r->c62 = Field::mul($this->c62, $c);
        $r->c63 = Field::mul($this->c63, $c);
        $r->c64 = Field::mul($this->c64, $c);
        $r->c65 = Field::mul($this->c65, $c);
        $r->c66 = Field::mul($this->c66, $c);
        $r->c67 = Field::mul($this->c67, $c);
        $r->c68 = Field::mul($this->c68, $c);
        $r->c69 = Field::mul($this->c69, $c);
        $r->c70 = Field::mul($this->c70, $c);
        $r->c71 = Field::mul($this->c71, $c);
        $r->c72 = Field::mul($this->c72, $c);
        $r->c73 = Field::mul($this->c73, $c);
        $r->c74 = Field::mul($this->c74, $c);
        $r->c75 = Field::mul($this->c75, $c);
        $r->c76 = Field::mul($this->c76, $c);
        $r->c77 = Field::mul($this->c77, $c);
        $r->c78 = Field::mul($this->c78, $c);
        $r->c79 = Field::mul($this->c79, $c);
        $r->c80 = Field::mul($this->c80, $c);
        $r->c81 = Field::mul($this->c81, $c);
        $r->c82 = Field::mul($this->c82, $c);
        $r->c83 = Field::mul($this->c83, $c);
        $r->c84 = Field::mul($this->c84, $c);
        $r->c85 = Field::mul($this->c85, $c);
        $r->c86 = Field::mul($this->c86, $c);
        $r->c87 = Field::mul($this->c87, $c);
        $r->c88 = Field::mul($this->c88, $c);
        $r->c89 = Field::mul($this->c89, $c);
        $r->c90 = Field::mul($this->c90, $c);
        $r->c91 = Field::mul($this->c91, $c);
        $r->c92 = Field::mul($this->c92, $c);
        $r->c93 = Field::mul($this->c93, $c);
        $r->c94 = Field::mul($this->c94, $c);
        $r->c95 = Field::mul($this->c95, $c);
        $r->c96 = Field::mul($this->c96, $c);
        $r->c97 = Field::mul($this->c97, $c);
        $r->c98 = Field::mul($this->c98, $c);
        $r->c99 = Field::mul($this->c99, $c);
        $r->c100 = Field::mul($this->c100, $c);
        $r->c101 = Field::mul($this->c101, $c);
        $r->c102 = Field::mul($this->c102, $c);
        $r->c103 = Field::mul($this->c103, $c);
        $r->c104 = Field::mul($this->c104, $c);
        $r->c105 = Field::mul($this->c105, $c);
        $r->c106 = Field::mul($this->c106, $c);
        $r->c107 = Field::mul($this->c107, $c);
        $r->c108 = Field::mul($this->c108, $c);
        $r->c109 = Field::mul($this->c109, $c);
        $r->c110 = Field::mul($this->c110, $c);
        $r->c111 = Field::mul($this->c111, $c);
        $r->c112 = Field::mul($this->c112, $c);
        $r->c113 = Field::mul($this->c113, $c);
        $r->c114 = Field::mul($this->c114, $c);
        $r->c115 = Field::mul($this->c115, $c);
        $r->c116 = Field::mul($this->c116, $c);
        $r->c117 = Field::mul($this->c117, $c);
        $r->c118 = Field::mul($this->c118, $c);
        $r->c119 = Field::mul($this->c119, $c);
        $r->c120 = Field::mul($this->c120, $c);
        $r->c121 = Field::mul($this->c121, $c);
        $r->c122 = Field::mul($this->c122, $c);
        $r->c123 = Field::mul($this->c123, $c);
        $r->c124 = Field::mul($this->c124, $c);
        $r->c125 = Field::mul($this->c125, $c);
        $r->c126 = Field::mul($this->c126, $c);
        $r->c127 = Field::mul($this->c127, $c);
        $r->c128 = Field::mul($this->c128, $c);
        $r->c129 = Field::mul($this->c129, $c);
        $r->c130 = Field::mul($this->c130, $c);
        $r->c131 = Field::mul($this->c131, $c);
        $r->c132 = Field::mul($this->c132, $c);
        $r->c133 = Field::mul($this->c133, $c);
        $r->c134 = Field::mul($this->c134, $c);
        $r->c135 = Field::mul($this->c135, $c);
        $r->c136 = Field::mul($this->c136, $c);
        $r->c137 = Field::mul($this->c137, $c);
        $r->c138 = Field::mul($this->c138, $c);
        $r->c139 = Field::mul($this->c139, $c);
        $r->c140 = Field::mul($this->c140, $c);
        $r->c141 = Field::mul($this->c141, $c);
        $r->c142 = Field::mul($this->c142, $c);
        $r->c143 = Field::mul($this->c143, $c);
        $r->c144 = Field::mul($this->c144, $c);
        $r->c145 = Field::mul($this->c145, $c);
        $r->c146 = Field::mul($this->c146, $c);
        $r->c147 = Field::mul($this->c147, $c);
        $r->c148 = Field::mul($this->c148, $c);
        $r->c149 = Field::mul($this->c149, $c);
        $r->c150 = Field::mul($this->c150, $c);
        $r->c151 = Field::mul($this->c151, $c);
        $r->c152 = Field::mul($this->c152, $c);
        $r->c153 = Field::mul($this->c153, $c);
        $r->c154 = Field::mul($this->c154, $c);
        $r->c155 = Field::mul($this->c155, $c);
        $r->c156 = Field::mul($this->c156, $c);
        $r->c157 = Field::mul($this->c157, $c);
        $r->c158 = Field::mul($this->c158, $c);
        $r->c159 = Field::mul($this->c159, $c);
        $r->c160 = Field::mul($this->c160, $c);
        $r->c161 = Field::mul($this->c161, $c);
        $r->c162 = Field::mul($this->c162, $c);
        $r->c163 = Field::mul($this->c163, $c);
        $r->c164 = Field::mul($this->c164, $c);
        $r->c165 = Field::mul($this->c165, $c);
        $r->c166 = Field::mul($this->c166, $c);
        $r->c167 = Field::mul($this->c167, $c);
        $r->c168 = Field::mul($this->c168, $c);
        $r->c169 = Field::mul($this->c169, $c);
        $r->c170 = Field::mul($this->c170, $c);
        $r->c171 = Field::mul($this->c171, $c);
        $r->c172 = Field::mul($this->c172, $c);
        $r->c173 = Field::mul($this->c173, $c);
        $r->c174 = Field::mul($this->c174, $c);
        $r->c175 = Field::mul($this->c175, $c);
        $r->c176 = Field::mul($this->c176, $c);
        $r->c177 = Field::mul($this->c177, $c);
        $r->c178 = Field::mul($this->c178, $c);
        $r->c179 = Field::mul($this->c179, $c);
        $r->c180 = Field::mul($this->c180, $c);
        $r->c181 = Field::mul($this->c181, $c);
        $r->c182 = Field::mul($this->c182, $c);
        $r->c183 = Field::mul($this->c183, $c);
        $r->c184 = Field::mul($this->c184, $c);
        $r->c185 = Field::mul($this->c185, $c);
        $r->c186 = Field::mul($this->c186, $c);
        $r->c187 = Field::mul($this->c187, $c);
        $r->c188 = Field::mul($this->c188, $c);
        $r->c189 = Field::mul($this->c189, $c);
        $r->c190 = Field::mul($this->c190, $c);
        $r->c191 = Field::mul($this->c191, $c);
        $r->c192 = Field::mul($this->c192, $c);
        $r->c193 = Field::mul($this->c193, $c);
        $r->c194 = Field::mul($this->c194, $c);
        $r->c195 = Field::mul($this->c195, $c);
        $r->c196 = Field::mul($this->c196, $c);
        $r->c197 = Field::mul($this->c197, $c);
        $r->c198 = Field::mul($this->c198, $c);
        $r->c199 = Field::mul($this->c199, $c);
        $r->c200 = Field::mul($this->c200, $c);
        $r->c201 = Field::mul($this->c201, $c);
        $r->c202 = Field::mul($this->c202, $c);
        $r->c203 = Field::mul($this->c203, $c);
        $r->c204 = Field::mul($this->c204, $c);
        $r->c205 = Field::mul($this->c205, $c);
        $r->c206 = Field::mul($this->c206, $c);
        $r->c207 = Field::mul($this->c207, $c);
        $r->c208 = Field::mul($this->c208, $c);
        $r->c209 = Field::mul($this->c209, $c);
        $r->c210 = Field::mul($this->c210, $c);
        $r->c211 = Field::mul($this->c211, $c);
        $r->c212 = Field::mul($this->c212, $c);
        $r->c213 = Field::mul($this->c213, $c);
        $r->c214 = Field::mul($this->c214, $c);
        $r->c215 = Field::mul($this->c215, $c);
        $r->c216 = Field::mul($this->c216, $c);
        $r->c217 = Field::mul($this->c217, $c);
        $r->c218 = Field::mul($this->c218, $c);
        $r->c219 = Field::mul($this->c219, $c);
        $r->c220 = Field::mul($this->c220, $c);
        $r->c221 = Field::mul($this->c221, $c);
        $r->c222 = Field::mul($this->c222, $c);
        $r->c223 = Field::mul($this->c223, $c);
        $r->c224 = Field::mul($this->c224, $c);
        $r->c225 = Field::mul($this->c225, $c);
        $r->c226 = Field::mul($this->c226, $c);
        $r->c227 = Field::mul($this->c227, $c);
        $r->c228 = Field::mul($this->c228, $c);
        $r->c229 = Field::mul($this->c229, $c);
        $r->c230 = Field::mul($this->c230, $c);
        $r->c231 = Field::mul($this->c231, $c);
        $r->c232 = Field::mul($this->c232, $c);
        $r->c233 = Field::mul($this->c233, $c);
        $r->c234 = Field::mul($this->c234, $c);
        $r->c235 = Field::mul($this->c235, $c);
        $r->c236 = Field::mul($this->c236, $c);
        $r->c237 = Field::mul($this->c237, $c);
        $r->c238 = Field::mul($this->c238, $c);
        $r->c239 = Field::mul($this->c239, $c);
        $r->c240 = Field::mul($this->c240, $c);
        $r->c241 = Field::mul($this->c241, $c);
        $r->c242 = Field::mul($this->c242, $c);
        $r->c243 = Field::mul($this->c243, $c);
        $r->c244 = Field::mul($this->c244, $c);
        $r->c245 = Field::mul($this->c245, $c);
        $r->c246 = Field::mul($this->c246, $c);
        $r->c247 = Field::mul($this->c247, $c);
        $r->c248 = Field::mul($this->c248, $c);
        $r->c249 = Field::mul($this->c249, $c);
        $r->c250 = Field::mul($this->c250, $c);
        $r->c251 = Field::mul($this->c251, $c);
        $r->c252 = Field::mul($this->c252, $c);
        $r->c253 = Field::mul($this->c253, $c);
        $r->c254 = Field::mul($this->c254, $c);
        $r->c255 = Field::mul($this->c255, $c);
        return $r;
    }

    public static function fromSymmetric(Ring $symmetric): Ring
    {
        $r = new Ring();
        $r->c0 = Field::newFromSymmetric($symmetric->c0);
        $r->c1 = Field::newFromSymmetric($symmetric->c1);
        $r->c2 = Field::newFromSymmetric($symmetric->c2);
        $r->c3 = Field::newFromSymmetric($symmetric->c3);
        $r->c4 = Field::newFromSymmetric($symmetric->c4);
        $r->c5 = Field::newFromSymmetric($symmetric->c5);
        $r->c6 = Field::newFromSymmetric($symmetric->c6);
        $r->c7 = Field::newFromSymmetric($symmetric->c7);
        $r->c8 = Field::newFromSymmetric($symmetric->c8);
        $r->c9 = Field::newFromSymmetric($symmetric->c9);
        $r->c10 = Field::newFromSymmetric($symmetric->c10);
        $r->c11 = Field::newFromSymmetric($symmetric->c11);
        $r->c12 = Field::newFromSymmetric($symmetric->c12);
        $r->c13 = Field::newFromSymmetric($symmetric->c13);
        $r->c14 = Field::newFromSymmetric($symmetric->c14);
        $r->c15 = Field::newFromSymmetric($symmetric->c15);
        $r->c16 = Field::newFromSymmetric($symmetric->c16);
        $r->c17 = Field::newFromSymmetric($symmetric->c17);
        $r->c18 = Field::newFromSymmetric($symmetric->c18);
        $r->c19 = Field::newFromSymmetric($symmetric->c19);
        $r->c20 = Field::newFromSymmetric($symmetric->c20);
        $r->c21 = Field::newFromSymmetric($symmetric->c21);
        $r->c22 = Field::newFromSymmetric($symmetric->c22);
        $r->c23 = Field::newFromSymmetric($symmetric->c23);
        $r->c24 = Field::newFromSymmetric($symmetric->c24);
        $r->c25 = Field::newFromSymmetric($symmetric->c25);
        $r->c26 = Field::newFromSymmetric($symmetric->c26);
        $r->c27 = Field::newFromSymmetric($symmetric->c27);
        $r->c28 = Field::newFromSymmetric($symmetric->c28);
        $r->c29 = Field::newFromSymmetric($symmetric->c29);
        $r->c30 = Field::newFromSymmetric($symmetric->c30);
        $r->c31 = Field::newFromSymmetric($symmetric->c31);
        $r->c32 = Field::newFromSymmetric($symmetric->c32);
        $r->c33 = Field::newFromSymmetric($symmetric->c33);
        $r->c34 = Field::newFromSymmetric($symmetric->c34);
        $r->c35 = Field::newFromSymmetric($symmetric->c35);
        $r->c36 = Field::newFromSymmetric($symmetric->c36);
        $r->c37 = Field::newFromSymmetric($symmetric->c37);
        $r->c38 = Field::newFromSymmetric($symmetric->c38);
        $r->c39 = Field::newFromSymmetric($symmetric->c39);
        $r->c40 = Field::newFromSymmetric($symmetric->c40);
        $r->c41 = Field::newFromSymmetric($symmetric->c41);
        $r->c42 = Field::newFromSymmetric($symmetric->c42);
        $r->c43 = Field::newFromSymmetric($symmetric->c43);
        $r->c44 = Field::newFromSymmetric($symmetric->c44);
        $r->c45 = Field::newFromSymmetric($symmetric->c45);
        $r->c46 = Field::newFromSymmetric($symmetric->c46);
        $r->c47 = Field::newFromSymmetric($symmetric->c47);
        $r->c48 = Field::newFromSymmetric($symmetric->c48);
        $r->c49 = Field::newFromSymmetric($symmetric->c49);
        $r->c50 = Field::newFromSymmetric($symmetric->c50);
        $r->c51 = Field::newFromSymmetric($symmetric->c51);
        $r->c52 = Field::newFromSymmetric($symmetric->c52);
        $r->c53 = Field::newFromSymmetric($symmetric->c53);
        $r->c54 = Field::newFromSymmetric($symmetric->c54);
        $r->c55 = Field::newFromSymmetric($symmetric->c55);
        $r->c56 = Field::newFromSymmetric($symmetric->c56);
        $r->c57 = Field::newFromSymmetric($symmetric->c57);
        $r->c58 = Field::newFromSymmetric($symmetric->c58);
        $r->c59 = Field::newFromSymmetric($symmetric->c59);
        $r->c60 = Field::newFromSymmetric($symmetric->c60);
        $r->c61 = Field::newFromSymmetric($symmetric->c61);
        $r->c62 = Field::newFromSymmetric($symmetric->c62);
        $r->c63 = Field::newFromSymmetric($symmetric->c63);
        $r->c64 = Field::newFromSymmetric($symmetric->c64);
        $r->c65 = Field::newFromSymmetric($symmetric->c65);
        $r->c66 = Field::newFromSymmetric($symmetric->c66);
        $r->c67 = Field::newFromSymmetric($symmetric->c67);
        $r->c68 = Field::newFromSymmetric($symmetric->c68);
        $r->c69 = Field::newFromSymmetric($symmetric->c69);
        $r->c70 = Field::newFromSymmetric($symmetric->c70);
        $r->c71 = Field::newFromSymmetric($symmetric->c71);
        $r->c72 = Field::newFromSymmetric($symmetric->c72);
        $r->c73 = Field::newFromSymmetric($symmetric->c73);
        $r->c74 = Field::newFromSymmetric($symmetric->c74);
        $r->c75 = Field::newFromSymmetric($symmetric->c75);
        $r->c76 = Field::newFromSymmetric($symmetric->c76);
        $r->c77 = Field::newFromSymmetric($symmetric->c77);
        $r->c78 = Field::newFromSymmetric($symmetric->c78);
        $r->c79 = Field::newFromSymmetric($symmetric->c79);
        $r->c80 = Field::newFromSymmetric($symmetric->c80);
        $r->c81 = Field::newFromSymmetric($symmetric->c81);
        $r->c82 = Field::newFromSymmetric($symmetric->c82);
        $r->c83 = Field::newFromSymmetric($symmetric->c83);
        $r->c84 = Field::newFromSymmetric($symmetric->c84);
        $r->c85 = Field::newFromSymmetric($symmetric->c85);
        $r->c86 = Field::newFromSymmetric($symmetric->c86);
        $r->c87 = Field::newFromSymmetric($symmetric->c87);
        $r->c88 = Field::newFromSymmetric($symmetric->c88);
        $r->c89 = Field::newFromSymmetric($symmetric->c89);
        $r->c90 = Field::newFromSymmetric($symmetric->c90);
        $r->c91 = Field::newFromSymmetric($symmetric->c91);
        $r->c92 = Field::newFromSymmetric($symmetric->c92);
        $r->c93 = Field::newFromSymmetric($symmetric->c93);
        $r->c94 = Field::newFromSymmetric($symmetric->c94);
        $r->c95 = Field::newFromSymmetric($symmetric->c95);
        $r->c96 = Field::newFromSymmetric($symmetric->c96);
        $r->c97 = Field::newFromSymmetric($symmetric->c97);
        $r->c98 = Field::newFromSymmetric($symmetric->c98);
        $r->c99 = Field::newFromSymmetric($symmetric->c99);
        $r->c100 = Field::newFromSymmetric($symmetric->c100);
        $r->c101 = Field::newFromSymmetric($symmetric->c101);
        $r->c102 = Field::newFromSymmetric($symmetric->c102);
        $r->c103 = Field::newFromSymmetric($symmetric->c103);
        $r->c104 = Field::newFromSymmetric($symmetric->c104);
        $r->c105 = Field::newFromSymmetric($symmetric->c105);
        $r->c106 = Field::newFromSymmetric($symmetric->c106);
        $r->c107 = Field::newFromSymmetric($symmetric->c107);
        $r->c108 = Field::newFromSymmetric($symmetric->c108);
        $r->c109 = Field::newFromSymmetric($symmetric->c109);
        $r->c110 = Field::newFromSymmetric($symmetric->c110);
        $r->c111 = Field::newFromSymmetric($symmetric->c111);
        $r->c112 = Field::newFromSymmetric($symmetric->c112);
        $r->c113 = Field::newFromSymmetric($symmetric->c113);
        $r->c114 = Field::newFromSymmetric($symmetric->c114);
        $r->c115 = Field::newFromSymmetric($symmetric->c115);
        $r->c116 = Field::newFromSymmetric($symmetric->c116);
        $r->c117 = Field::newFromSymmetric($symmetric->c117);
        $r->c118 = Field::newFromSymmetric($symmetric->c118);
        $r->c119 = Field::newFromSymmetric($symmetric->c119);
        $r->c120 = Field::newFromSymmetric($symmetric->c120);
        $r->c121 = Field::newFromSymmetric($symmetric->c121);
        $r->c122 = Field::newFromSymmetric($symmetric->c122);
        $r->c123 = Field::newFromSymmetric($symmetric->c123);
        $r->c124 = Field::newFromSymmetric($symmetric->c124);
        $r->c125 = Field::newFromSymmetric($symmetric->c125);
        $r->c126 = Field::newFromSymmetric($symmetric->c126);
        $r->c127 = Field::newFromSymmetric($symmetric->c127);
        $r->c128 = Field::newFromSymmetric($symmetric->c128);
        $r->c129 = Field::newFromSymmetric($symmetric->c129);
        $r->c130 = Field::newFromSymmetric($symmetric->c130);
        $r->c131 = Field::newFromSymmetric($symmetric->c131);
        $r->c132 = Field::newFromSymmetric($symmetric->c132);
        $r->c133 = Field::newFromSymmetric($symmetric->c133);
        $r->c134 = Field::newFromSymmetric($symmetric->c134);
        $r->c135 = Field::newFromSymmetric($symmetric->c135);
        $r->c136 = Field::newFromSymmetric($symmetric->c136);
        $r->c137 = Field::newFromSymmetric($symmetric->c137);
        $r->c138 = Field::newFromSymmetric($symmetric->c138);
        $r->c139 = Field::newFromSymmetric($symmetric->c139);
        $r->c140 = Field::newFromSymmetric($symmetric->c140);
        $r->c141 = Field::newFromSymmetric($symmetric->c141);
        $r->c142 = Field::newFromSymmetric($symmetric->c142);
        $r->c143 = Field::newFromSymmetric($symmetric->c143);
        $r->c144 = Field::newFromSymmetric($symmetric->c144);
        $r->c145 = Field::newFromSymmetric($symmetric->c145);
        $r->c146 = Field::newFromSymmetric($symmetric->c146);
        $r->c147 = Field::newFromSymmetric($symmetric->c147);
        $r->c148 = Field::newFromSymmetric($symmetric->c148);
        $r->c149 = Field::newFromSymmetric($symmetric->c149);
        $r->c150 = Field::newFromSymmetric($symmetric->c150);
        $r->c151 = Field::newFromSymmetric($symmetric->c151);
        $r->c152 = Field::newFromSymmetric($symmetric->c152);
        $r->c153 = Field::newFromSymmetric($symmetric->c153);
        $r->c154 = Field::newFromSymmetric($symmetric->c154);
        $r->c155 = Field::newFromSymmetric($symmetric->c155);
        $r->c156 = Field::newFromSymmetric($symmetric->c156);
        $r->c157 = Field::newFromSymmetric($symmetric->c157);
        $r->c158 = Field::newFromSymmetric($symmetric->c158);
        $r->c159 = Field::newFromSymmetric($symmetric->c159);
        $r->c160 = Field::newFromSymmetric($symmetric->c160);
        $r->c161 = Field::newFromSymmetric($symmetric->c161);
        $r->c162 = Field::newFromSymmetric($symmetric->c162);
        $r->c163 = Field::newFromSymmetric($symmetric->c163);
        $r->c164 = Field::newFromSymmetric($symmetric->c164);
        $r->c165 = Field::newFromSymmetric($symmetric->c165);
        $r->c166 = Field::newFromSymmetric($symmetric->c166);
        $r->c167 = Field::newFromSymmetric($symmetric->c167);
        $r->c168 = Field::newFromSymmetric($symmetric->c168);
        $r->c169 = Field::newFromSymmetric($symmetric->c169);
        $r->c170 = Field::newFromSymmetric($symmetric->c170);
        $r->c171 = Field::newFromSymmetric($symmetric->c171);
        $r->c172 = Field::newFromSymmetric($symmetric->c172);
        $r->c173 = Field::newFromSymmetric($symmetric->c173);
        $r->c174 = Field::newFromSymmetric($symmetric->c174);
        $r->c175 = Field::newFromSymmetric($symmetric->c175);
        $r->c176 = Field::newFromSymmetric($symmetric->c176);
        $r->c177 = Field::newFromSymmetric($symmetric->c177);
        $r->c178 = Field::newFromSymmetric($symmetric->c178);
        $r->c179 = Field::newFromSymmetric($symmetric->c179);
        $r->c180 = Field::newFromSymmetric($symmetric->c180);
        $r->c181 = Field::newFromSymmetric($symmetric->c181);
        $r->c182 = Field::newFromSymmetric($symmetric->c182);
        $r->c183 = Field::newFromSymmetric($symmetric->c183);
        $r->c184 = Field::newFromSymmetric($symmetric->c184);
        $r->c185 = Field::newFromSymmetric($symmetric->c185);
        $r->c186 = Field::newFromSymmetric($symmetric->c186);
        $r->c187 = Field::newFromSymmetric($symmetric->c187);
        $r->c188 = Field::newFromSymmetric($symmetric->c188);
        $r->c189 = Field::newFromSymmetric($symmetric->c189);
        $r->c190 = Field::newFromSymmetric($symmetric->c190);
        $r->c191 = Field::newFromSymmetric($symmetric->c191);
        $r->c192 = Field::newFromSymmetric($symmetric->c192);
        $r->c193 = Field::newFromSymmetric($symmetric->c193);
        $r->c194 = Field::newFromSymmetric($symmetric->c194);
        $r->c195 = Field::newFromSymmetric($symmetric->c195);
        $r->c196 = Field::newFromSymmetric($symmetric->c196);
        $r->c197 = Field::newFromSymmetric($symmetric->c197);
        $r->c198 = Field::newFromSymmetric($symmetric->c198);
        $r->c199 = Field::newFromSymmetric($symmetric->c199);
        $r->c200 = Field::newFromSymmetric($symmetric->c200);
        $r->c201 = Field::newFromSymmetric($symmetric->c201);
        $r->c202 = Field::newFromSymmetric($symmetric->c202);
        $r->c203 = Field::newFromSymmetric($symmetric->c203);
        $r->c204 = Field::newFromSymmetric($symmetric->c204);
        $r->c205 = Field::newFromSymmetric($symmetric->c205);
        $r->c206 = Field::newFromSymmetric($symmetric->c206);
        $r->c207 = Field::newFromSymmetric($symmetric->c207);
        $r->c208 = Field::newFromSymmetric($symmetric->c208);
        $r->c209 = Field::newFromSymmetric($symmetric->c209);
        $r->c210 = Field::newFromSymmetric($symmetric->c210);
        $r->c211 = Field::newFromSymmetric($symmetric->c211);
        $r->c212 = Field::newFromSymmetric($symmetric->c212);
        $r->c213 = Field::newFromSymmetric($symmetric->c213);
        $r->c214 = Field::newFromSymmetric($symmetric->c214);
        $r->c215 = Field::newFromSymmetric($symmetric->c215);
        $r->c216 = Field::newFromSymmetric($symmetric->c216);
        $r->c217 = Field::newFromSymmetric($symmetric->c217);
        $r->c218 = Field::newFromSymmetric($symmetric->c218);
        $r->c219 = Field::newFromSymmetric($symmetric->c219);
        $r->c220 = Field::newFromSymmetric($symmetric->c220);
        $r->c221 = Field::newFromSymmetric($symmetric->c221);
        $r->c222 = Field::newFromSymmetric($symmetric->c222);
        $r->c223 = Field::newFromSymmetric($symmetric->c223);
        $r->c224 = Field::newFromSymmetric($symmetric->c224);
        $r->c225 = Field::newFromSymmetric($symmetric->c225);
        $r->c226 = Field::newFromSymmetric($symmetric->c226);
        $r->c227 = Field::newFromSymmetric($symmetric->c227);
        $r->c228 = Field::newFromSymmetric($symmetric->c228);
        $r->c229 = Field::newFromSymmetric($symmetric->c229);
        $r->c230 = Field::newFromSymmetric($symmetric->c230);
        $r->c231 = Field::newFromSymmetric($symmetric->c231);
        $r->c232 = Field::newFromSymmetric($symmetric->c232);
        $r->c233 = Field::newFromSymmetric($symmetric->c233);
        $r->c234 = Field::newFromSymmetric($symmetric->c234);
        $r->c235 = Field::newFromSymmetric($symmetric->c235);
        $r->c236 = Field::newFromSymmetric($symmetric->c236);
        $r->c237 = Field::newFromSymmetric($symmetric->c237);
        $r->c238 = Field::newFromSymmetric($symmetric->c238);
        $r->c239 = Field::newFromSymmetric($symmetric->c239);
        $r->c240 = Field::newFromSymmetric($symmetric->c240);
        $r->c241 = Field::newFromSymmetric($symmetric->c241);
        $r->c242 = Field::newFromSymmetric($symmetric->c242);
        $r->c243 = Field::newFromSymmetric($symmetric->c243);
        $r->c244 = Field::newFromSymmetric($symmetric->c244);
        $r->c245 = Field::newFromSymmetric($symmetric->c245);
        $r->c246 = Field::newFromSymmetric($symmetric->c246);
        $r->c247 = Field::newFromSymmetric($symmetric->c247);
        $r->c248 = Field::newFromSymmetric($symmetric->c248);
        $r->c249 = Field::newFromSymmetric($symmetric->c249);
        $r->c250 = Field::newFromSymmetric($symmetric->c250);
        $r->c251 = Field::newFromSymmetric($symmetric->c251);
        $r->c252 = Field::newFromSymmetric($symmetric->c252);
        $r->c253 = Field::newFromSymmetric($symmetric->c253);
        $r->c254 = Field::newFromSymmetric($symmetric->c254);
        $r->c255 = Field::newFromSymmetric($symmetric->c255);
        return $r;
    }

    public function offsetExists(mixed $offset): bool
    {
        return $offset >= 0 && $offset < 256;
    }

    public function offsetGet(mixed $offset): int
    {
        return $this->{'c' . $offset};
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->{'c' . $offset} = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        $this->{'c' . $offset} = 0;
    }
}