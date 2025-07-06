#include <cstdint>
#include <stdexcept>
#include <unordered_set>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <array>

struct instruction_length {
    size_t prefix_len;
    size_t opcode_len;
    size_t modrm_len;
    size_t sib_len;
    size_t displacement_len;
    size_t immediate_len;
    size_t total_len;
};

static std::string bytes_to_hex(const uint8_t* data, size_t len) noexcept {
    if (len == 0) return "";
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
        if (i < len - 1) oss << " ";
    }
    return oss.str();
}

class instruction_decoder {
public:
    static instruction_length decode_instruction_length(const uint8_t* code, size_t buffer_size) {
        instruction_length len = {};
        size_t offset = 0;

        // Parse prefixes
        len.prefix_len = parse_prefixes(code, buffer_size, offset);

        // Check for VEX/EVEX/XOP
        bool has_vex = false;
        bool is_evex = false;
        bool is_xop = false;
        std::array<uint8_t, 4> vex_prefix = { 0 };
        if (offset < buffer_size) {
            if (code[offset] == 0xC4 || code[offset] == 0xC5) { // VEX
                size_t vex_len = (code[offset] == 0xC4) ? 3 : 2;
                if (offset + vex_len > buffer_size)
                    throw std::runtime_error("Incomplete VEX prefix");

                for (size_t i = 0; i < vex_len; i++) {
                    vex_prefix[i] = code[offset + i];
                }

                len.prefix_len += vex_len;
                offset = len.prefix_len;
                has_vex = true;
            }
            else if (offset < buffer_size && code[offset] == 0x62) { // EVEX
                if (offset + 4 > buffer_size)
                    throw std::runtime_error("Incomplete EVEX prefix");

                for (int i = 0; i < 4; i++) {
                    vex_prefix[i] = code[offset + i];
                }

                len.prefix_len += 4;
                offset = len.prefix_len;
                has_vex = true;
                is_evex = true;
            }
            else if (offset < buffer_size && code[offset] == 0x8F) { // XOP
                if (offset + 3 > buffer_size)
                    throw std::runtime_error("Incomplete XOP prefix");

                for (int i = 0; i < 3; i++) {
                    vex_prefix[i] = code[offset + i];
                }

                len.prefix_len += 3;
                offset = len.prefix_len;
                has_vex = true;
                is_xop = true;
            }
        }

        // Parse opcode
        if (offset >= buffer_size) throw std::runtime_error("No opcode found");
        len.opcode_len = parse_opcode(code, buffer_size, offset, has_vex, is_evex, is_xop, vex_prefix);

        // Check if ModR/M is needed
        bool modrm_present = is_modrm_present(
            code + len.prefix_len, len.opcode_len,
            has_vex, is_evex, is_xop, vex_prefix
        );

        uint8_t modrm_byte = 0;
        if (modrm_present) {
            if (offset >= buffer_size) throw std::runtime_error("Missing ModR/M byte");
            len.modrm_len = 1;
            modrm_byte = code[offset++];

            // Parse SIB
            len.sib_len = parse_sib(modrm_byte, code, buffer_size, offset);

            // Parse displacement
            len.displacement_len = parse_displacement(modrm_byte, code, buffer_size, offset);
        }

        // Parse immediate
        len.immediate_len = parse_immediate(
            code, len.prefix_len, len.opcode_len,
            has_vex, is_evex, is_xop, modrm_present, modrm_byte, vex_prefix
        );
        offset += len.immediate_len; // Update offset with immediate length

        // Calculate total length
        len.total_len = offset;

        // Validate buffer size
        if (len.total_len > buffer_size) {
            std::ostringstream oss;
            oss << "Insufficient buffer for full instruction (needed "
                << len.total_len << " bytes, got " << buffer_size << ")";
            throw std::runtime_error(oss.str());
        }

        return len;
    }

private:
    static size_t parse_prefixes(const uint8_t* code, size_t size, size_t& offset) noexcept {
        size_t start = offset;
        while (offset < size) {
            uint8_t b = code[offset];

            // Legacy prefixes
            if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||   // LOCK/REPNE/REP
                b == 0x2E || b == 0x36 || b == 0x3E ||   // CS/SS/DS
                b == 0x26 || b == 0x64 || b == 0x65 ||   // ES/FS/GS
                b == 0x66 || b == 0x67) {                // Operand/Address size
                offset++;
            }
            // REX prefix (x64)
            else if ((b & 0xF0) == 0x40) {
                offset++;
            }
            // VEX/EVEX/XOP prefixes (handled later)
            else if (b == 0xC4 || b == 0xC5 || b == 0x62 || b == 0x8F) {
                break;
            }
            // Non-prefix byte
            else {
                break;
            }
        }
        return offset - start;
    }

    static size_t parse_opcode(const uint8_t* code, size_t size, size_t& offset,
        bool has_vex, bool is_evex, bool is_xop,
        const std::array<uint8_t, 4>& vex_prefix) {
        size_t start = offset;

        // VEX/EVEX/XOP instructions have 1-byte opcode
        if (has_vex) {
            if (offset < size) {
                offset++;
                return 1;
            }
            throw std::runtime_error("Missing VEX/EVEX/XOP opcode");
        }

        // Standard instruction opcode
        if (offset < size) {
            uint8_t b1 = code[offset++];

            // FPU instructions (0xD8-0xDF) - now handled as 1-byte opcode
            if (b1 >= 0xD8 && b1 <= 0xDF) {
                return 1;
            }

            // Multi-byte opcodes
            if (b1 == 0x0F) {
                if (offset >= size) throw std::runtime_error("Incomplete 0F opcode");
                uint8_t b2 = code[offset++];

                // 3DNow! instructions
                if (b2 == 0x0F) {
                    return 2;
                }

                // 3-byte opcodes (0F 38 or 0F 3A)
                if (b2 == 0x38 || b2 == 0x3A) {
                    if (offset >= size) throw std::runtime_error("Incomplete 3-byte opcode");
                    offset++;
                    return 3;
                }

                return 2; // 2-byte opcode (0F XX)
            }

            return 1; // 1-byte opcode
        }

        throw std::runtime_error("No opcode found");
    }

    static bool is_modrm_present(const uint8_t* opcode, size_t opcode_len,
        bool has_vex, bool is_evex, bool is_xop,
        const std::array<uint8_t, 4>& vex_prefix) noexcept {
        // VEX/EVEX/XOP instructions always have ModR/M
        if (has_vex) return true;

        // 1-byte opcode
        if (opcode_len == 1) {
            uint8_t b = opcode[0];

            // Instructions without ModR/M
            static const std::unordered_set<uint8_t> no_modrm_ops = {
                0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F, // Segment ops
                0x60, 0x61, 0x62, 0x63, // PUSHAD/POPAD/BOUND
                0x68, 0x6A,             // PUSH
                0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, // XCHG
                0x98, 0x99,             // CBW/CWD
                0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, // CALLF/PUSHF/POPF/SAHF/LAHF
                0xA0, 0xA1, 0xA2, 0xA3, // MOV moffs
                0xA4, 0xA5,             // MOVS
                0xA6, 0xA7,             // CMPS
                0xA8, 0xA9,             // TEST AL/AX
                0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, // STOS/LODS/SCAS
                0xC2, 0xC3, 0xC9, 0xCA, 0xCB, // RET
                0xCC, 0xCD, 0xCE, 0xCF, // INT/INTO/IRET
                0xD4, 0xD5, 0xD6,       // AAM/AAD/SALC
                0xD7,                   // XLAT
                0xE0, 0xE1, 0xE2, 0xE3, // LOOP/JCXZ
                0xE8, 0xE9, 0xEB,       // CALL/JMP
                0xF1,                   // INT1
                0xF4, 0xF5, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, // HLT/CMC/CLC/STC/CLI/STI/CLD/STD
                0x0F, 0xA0, 0xA1, 0xA8, 0xA9 // PUSH/POP FS/GS
            };

            // Range checks
            if ((b >= 0x50 && b <= 0x5F) ||  // PUSH/POP reg
                (b >= 0xB0 && b <= 0xBF) ||  // MOV reg, imm
                (b >= 0x70 && b <= 0x7F)) {  // Jcc rel8
                return false;
            }

            return no_modrm_ops.find(b) == no_modrm_ops.end();
        }

        // 2-byte opcode (0F XX)
        if (opcode_len == 2) {
            uint16_t op = (static_cast<uint16_t>(opcode[0]) << 8 | opcode[1]);

            // Instructions without ModR/M
            static const std::unordered_set<uint16_t> no_modrm_ops = {
                0x0F00, 0x0F01, 0x0F04, 0x0F05, 0x0F06, 0x0F07, 0x0F08, 0x0F09,
                0x0F0A, 0x0F0B, 0x0F18, 0x0F30, 0x0F31, 0x0F32, 0x0F33, 0x0F34,
                0x0F35, 0x0F37, 0x0F60, 0x0F61, 0x0F62, 0x0F63, 0x0F77, 0x0FAE,
                0x0FAF, 0x0FB9, 0x0F00, 0x0F01, // Group 6
                0x0F08, 0x0F09, 0x0F10, 0x0F11, // INVD/WBINVD/UD1/UD2
                0x0F18, 0x0F1F,                 // PREFETCH/NOP
                0x0F20, 0x0F21, 0x0F22, 0x0F23, // MOV to/from CR/DR/TR
                0x0F30, 0x0F31, 0x0F32, 0x0F33, 0x0F34, 0x0F35, // WRMSR/RDTSC/RDMSR/RDPMC/SYSENTER/SYSEXIT
                0x0F60, 0x0F61, 0x0F62, 0x0F63, // PUNPCK
                0x0FA0, 0x0FA1, 0x0FA8, 0x0FA9, // PUSH/POP FS/GS
                0x0FAB, 0x0FAD,                 // BTS/SHRD
                0x0FAE, 0x0FAF,                 // FXSAVE/FXRSTOR
                0x0FB8, 0x0FB9,                 // JMPE/POPCNT
                0x0F71, 0x0F72, 0x0F73,         // PSRL/PSRA/PSLL
                0x0F01, 0x0F10, 0x0F11, 0x0F28, 0x0F29, 0x0F50, 0x0F54, 0x0F55, 0x0F56, 0x0F57, 0x0F58, 0x0F59, 0x0F5A, 0x0F5B, 0x0F5C, 0x0F5D, 0x0F5E, 0x0F5F, 0x0F68, 0x0F69, 0x0F6A, 0x0F6B, 0x0F6C, 0x0F6D, 0x0F6E, 0x0F6F, 0x0F70, 0x0F7E, 0x0F7F, 0x0F90, 0x0F91, 0x0F92, 0x0F93, 0x0F94, 0x0F95, 0x0F96, 0x0F97, 0x0F98, 0x0F99, 0x0F9A, 0x0F9B, 0x0F9C, 0x0F9D, 0x0F9E, 0x0F9F, 0x0FA0, 0x0FA1, 0x0FA2, 0x0FA3, 0x0FA4, 0x0FA5, 0x0FA6, 0x0FA7, 0x0FAA, 0x0FAC, 0x0FAD, 0x0FAE, 0x0FAF, 0x0FB0, 0x0FB1, 0x0FB2, 0x0FB3, 0x0FB4, 0x0FB5, 0x0FB6, 0x0FB7, 0x0FBC, 0x0FBD, 0x0FBE, 0x0FBF, 0x0FC0, 0x0FC1, 0x0FC2, 0x0FC3, 0x0FC4, 0x0FC5, 0x0FC6, 0x0FC7, 0x0FD0, 0x0FD1, 0x0FD2, 0x0FD3, 0x0FD4, 0x0FD5, 0x0FD6, 0x0FD7, 0x0FD8, 0x0FD9, 0x0FDA, 0x0FDB, 0x0FDC, 0x0FDD, 0x0FDE, 0x0FDF, 0x0FE0, 0x0FE1, 0x0FE2, 0x0FE3, 0x0FE4, 0x0FE5, 0x0FE6, 0x0FE7, 0x0FE8, 0x0FE9, 0x0FEA, 0x0FEB, 0x0FEC, 0x0FED, 0x0FEE, 0x0FEF, 0x0FF0, 0x0FF1, 0x0FF2, 0x0FF3, 0x0FF4, 0x0FF5, 0x0FF6, 0x0FF7, 0x0FF8, 0x0FF9, 0x0FFA, 0x0FFB, 0x0FFC, 0x0FFD, 0x0FFE, 0x0FFF
            };

            // Conditional jumps (0F 80-8F)
            if (op >= 0x0F80 && op <= 0x0F8F) return false;

            // FPU instructions
            if (opcode[0] >= 0xD8 && opcode[0] <= 0xDF) return true;

            // VMX instructions (0F 01 with ModR/M)
            if (op == 0x0F01) {
                return true;
            }

            return no_modrm_ops.find(op) == no_modrm_ops.end();
        }

        // 3-byte opcode (0F 38 XX or 0F 3A XX or 3DNow!)
        if (opcode_len == 3) {
            // 3DNow! instructions
            if (opcode[0] == 0x0F && opcode[1] == 0x0F) return true;

            // All other 3-byte opcodes have ModR/M
            return true;
        }

        return true;
    }

    static size_t parse_sib(uint8_t modrm, const uint8_t* code, size_t size, size_t& offset) {
        uint8_t mod = modrm >> 6;
        uint8_t rm = modrm & 0x07;

        // 32/64-bit mode requires SIB when mod != 11 and rm = 100
        if (mod != 0b11 && rm == 0b100) {
            if (offset >= size) throw std::runtime_error("Missing SIB byte");
            offset++;
            return 1;
        }
        return 0;
    }

    static size_t parse_displacement(uint8_t modrm, const uint8_t* code, size_t size, size_t& offset) {
        uint8_t mod = modrm >> 6;
        uint8_t rm = modrm & 0x07;

        // RIP-relative addressing (x64)
        if (rm == 0b101 && mod == 0b00) {
            if (offset + 4 > size) throw std::runtime_error("Missing displacement");
            offset += 4;
            return 4;
        }

        // Direct addressing (no SIB) in 32-bit mode
        if (mod == 0b00 && rm == 0b101) {
            if (offset + 4 > size) throw std::runtime_error("Missing displacement");
            offset += 4;
            return 4;
        }

        // 8-bit displacement
        if (mod == 0b01) {
            if (offset >= size) throw std::runtime_error("Missing displacement");
            offset++;
            return 1;
        }

        // 32-bit displacement
        if (mod == 0b10) {
            if (offset + 4 > size) throw std::runtime_error("Missing displacement");
            offset += 4;
            return 4;
        }

        return 0;
    }

    static bool has_rex_w_prefix(const uint8_t* code, size_t prefix_len) noexcept {
        for (size_t i = 0; i < prefix_len; ++i) {
            if ((code[i] & 0xF0) == 0x40 &&  // REX prefix
                (code[i] & 0x08)) {          // REX.W bit
                return true;
            }
        }
        return false;
    }

    static bool has_operand_size_prefix(const uint8_t* code, size_t prefix_len) noexcept {
        for (size_t i = 0; i < prefix_len; ++i) {
            if (code[i] == 0x66) return true;
        }
        return false;
    }

    static bool has_address_size_prefix(const uint8_t* code, size_t prefix_len) noexcept {
        for (size_t i = 0; i < prefix_len; ++i) {
            if (code[i] == 0x67) return true;
        }
        return false;
    }

    static size_t parse_immediate(const uint8_t* code, size_t prefix_len, size_t opcode_len,
        bool has_vex, bool is_evex, bool is_xop,
        bool has_modrm, uint8_t modrm,
        const std::array<uint8_t, 4>& vex_prefix) noexcept {
        const uint8_t* opcode_ptr = code + prefix_len;
        uint8_t op1 = opcode_ptr[0];
        bool rex_w = has_rex_w_prefix(code, prefix_len);
        bool op_size = has_operand_size_prefix(code, prefix_len);
        bool addr_size = has_address_size_prefix(code, prefix_len);

        // Handle 3DNow! instructions (0F 0F)
        if (opcode_len == 2 && op1 == 0x0F && opcode_ptr[1] == 0x0F) {
            return 1; // 3DNow! has 1-byte immediate
        }

        // VEX/EVEX/XOP instructions
        if (has_vex) {
            uint8_t vex_op = opcode_ptr[0];

            // Handle XOP instructions
            if (is_xop) {
                if (opcode_len > 1) {
                    uint8_t xop_map = vex_prefix[1] & 0x1F;
                    uint8_t xop_op = opcode_ptr[1];

                    // XOP immediate instructions
                    if (xop_map == 0x08) {
                        if (xop_op == 0x80 || xop_op == 0x81 || xop_op == 0x82 ||
                            xop_op == 0x83 || xop_op == 0x84 || xop_op == 0x85) {
                            return 1; // VPERMIL2PD/PS with imm8
                        }
                    }
                    else if (xop_map == 0x09) {
                        if (xop_op == 0x00 || xop_op == 0x01 || xop_op == 0x02 ||
                            xop_op == 0x03 || xop_op == 0x04) {
                            return 1; // VPPERM with imm8
                        }
                    }
                    else if (xop_map == 0x0A) {
                        if (xop_op == 0x80 || xop_op == 0x81 || xop_op == 0x82 ||
                            xop_op == 0x83 || xop_op == 0x84 || xop_op == 0x85) {
                            return 1; // VPCMOV with imm8
                        }
                    }
                }
                return 0;
            }

            // AVX/AVX2/AVX512 instructions
            switch (vex_op) {
                // Instructions with imm8
            case 0xC2: case 0xC4: case 0xC5: case 0xC6: // VCMP, VPINSRW, VPEXTRW
            case 0x70: case 0x71: case 0x72: case 0x73: // VPSHUFD, VPSRLW, etc
            case 0x1F: case 0x19: case 0x39:            // VEXTRACTF128, VINSERTF128
            case 0x3A:                                  // VPERMIL2PD/PS
            case 0x4A: case 0x4B:                       // VBLENDVPD/PS, VPBLENDVB, VPBLENDW
            case 0x74: /*case 0x75:*/ case 0x76: case 0x77: // VPCMOV
            case 0x0F: case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x18: case 0x1A: case 0x1B: case 0x1C: case 0x1D: case 0x1E: // AVX512
                return 1;

                // FMA instructions
            case 0x98: case 0x99: case 0x9A: case 0x9B:
            case 0x9C: case 0x9D: case 0x9E: case 0x9F:
            case 0xA8: case 0xA9: case 0xAA: case 0xAB:
            case 0xAC: case 0xAD: case 0xAE: case 0xAF:
            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                return 0; // No immediate

                // AVX512 instructions
            case 0x62:
                if (opcode_len > 0) {
                    uint8_t avx512_op = opcode_ptr[0];
                    if (avx512_op == 0x70 || avx512_op == 0x71 || avx512_op == 0x72 ||
                        avx512_op == 0x73 || avx512_op == 0xC2 || avx512_op == 0x1F ||
                        avx512_op == 0x3A || avx512_op == 0x4A || avx512_op == 0x4B) {
                        return 1;
                    }
                }
                return 0;

            default:
                return 0;
            }
        }

        // FPU instructions - no immediate
        if (opcode_len == 1 && op1 >= 0xD8 && op1 <= 0xDF) {
            return 0;
        }

        // 1-byte opcode
        if (opcode_len == 1) {
            switch (op1) {
                // Jump instructions
            case 0xE8: case 0xE9: return 4;  // CALL/JMP rel32
            case 0xEB: return 1;              // JMP rel8

                // Conditional jumps
            case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
            case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
            case 0x7C: case 0x7D: case 0x7E: case 0x7F: return 1; // Jcc rel8

                // MOV instructions
            case 0xB0: case 0xB1: case 0xB2: case 0xB3:
            case 0xB4: case 0xB5: case 0xB6: case 0xB7: return 1; // MOV r8, imm8

            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF: // MOV r32/r64, imm32/imm64
                return rex_w ? 8 : 4;

            case 0xC6: // MOV r/m8, imm8
                if (!has_modrm) return 1;
                return (modrm >> 3 & 7) == 0 ? 1 : 0;

            case 0xC7: // MOV r/m32, imm32
                if (!has_modrm) return rex_w ? 8 : 4;
                return (modrm >> 3 & 7) == 0 ? (rex_w ? 8 : 4) : 0;

                // Stack operations
            case 0x68: return rex_w ? 8 : 4; // PUSH imm32
            case 0x6A: return 1;             // PUSH imm8

                // Arithmetic instructions
            case 0x04: case 0x0C: case 0x14: case 0x1C:
            case 0x24: case 0x2C: case 0x34: case 0x3C: return 1; // ALU AL, imm8

            case 0x05: case 0x0D: case 0x15: case 0x1D:
            case 0x25: case 0x2D: case 0x35: case 0x3D: // ALU EAX, imm32
                return rex_w ? 8 : 4;

            case 0x80: // ALU r/m8, imm8
                return has_modrm ? 1 : 0;

            case 0x81: // ALU r/m32, imm32
                return has_modrm ? (rex_w ? 8 : 4) : 0;

            case 0x83: // ALU r/m32, imm8
                return has_modrm ? 1 : 0;

                // Shift instructions
            case 0xC0: case 0xC1: // ROL/ROR/RCL/RCR/SHL/SHR/SAR r/m, imm8
            case 0xD0: case 0xD1: case 0xD2: case 0xD3: // Shift with CL
                return has_modrm ? 1 : 0;

                // Special instructions
            case 0xA0: case 0xA1: case 0xA2: case 0xA3: return 4; // MOV moffs
            case 0xE0: case 0xE1: case 0xE2: return 1; // LOOP/LOOPE/LOOPNE
            case 0xCD: return 1; // INT imm8
            case 0xE4: case 0xE5: return 1; // IN AL/AX, imm8
            case 0xE6: case 0xE7: return 1; // OUT imm8, AL/AX
            case 0xEC: case 0xED: return 0; // IN AL/AX, DX
            case 0xEE: case 0xEF: return 0; // OUT DX, AL/AX
            case 0xF6: case 0xF7: // TEST r/m, imm
                if (!has_modrm) return rex_w && op1 == 0xF7 ? 8 : 4;
                return (modrm >> 3 & 7) == 0 ? (rex_w && op1 == 0xF7 ? 8 : 4) : 0;

            default:
                return 0;
            }
        }

        // 2-byte opcode (0F XX)
        if (opcode_len == 2) {
            uint8_t op2 = opcode_ptr[1];
            uint16_t opcode16 = (static_cast<uint16_t>(op1) << 8) | op2;

            switch (opcode16) {
                // Conditional jumps
            case 0x0F80: case 0x0F81: case 0x0F82: case 0x0F83:
            case 0x0F84: case 0x0F85: case 0x0F86: case 0x0F87:
            case 0x0F88: case 0x0F89: case 0x0F8A: case 0x0F8B:
            case 0x0F8C: case 0x0F8D: case 0x0F8E: case 0x0F8F:
                return 4; // Jcc rel32

                // Bit test
            case 0x0FBA:
                return has_modrm ? 1 : 0; // BT/BTS/etc + imm8

                // SSE instructions
            case 0x0F70: return 1; // PSHUFW imm8
            case 0x0FC2: return 1; // CMPPS imm8
            case 0x0F3A: return 1; // PCLMULQDQ imm8
            case 0x0F71: case 0x0F72: case 0x0F73: // PSRL/PSRA/PSLL with imm8
                return 1;
            case 0x0F6F: case 0x0F7F: // MOVQ
                return 0;

                // AES instructions
            case 0x0F38DB: case 0x0F38DC: case 0x0F38DD: case 0x0F38DE: // AES
            case 0x0F38DF:
                return 0;
            case 0x0F3ADF: return 1; // AESKEYGENASSIST imm8

                // SHA instructions
            case 0x0F38C8: case 0x0F38C9: case 0x0F38CA: case 0x0F38CB: // SHA
            case 0x0F38CC: case 0x0F38CD: case 0x0F38CE:
                return 0;
            case 0x0F38D0: return 0; // MOVBE

                // 3DNow! instructions - handled earlier
            case 0x0F0F:
                return 0;

                // System instructions
            case 0x0F34: case 0x0F35: // SYSENTER/SYSEXIT
                return 0;

                // MMX instructions
            case 0x0F6E: case 0x0F7E: // MOVD
            case 0x0FE4: case 0x0FE5: // PMULHUW, PMULHW
            case 0x0FD4: case 0x0FD5: // PADDQ, PSUBQ
            case 0x0F74: case 0x0F75: // PCMPEQB/W/D
            case 0x0F76: // PCMPEQD
            case 0x0FC4: case 0x0FC5: // PINSRW/PEXTRW
            case 0x0FF0: case 0x0FF1: // PSHUFLW/PSHUFHW
                return 0;

                // SSE4A
            case 0x0F78: case 0x0F79: // MOVNTSS, MOVNTSD
                return 0;

                // XSAVE
            case 0x0FAE: // XSAVE/XSAVEOPT
                if (has_modrm) {
                    uint8_t ext = (modrm >> 3) & 7;
                    if (ext == 4 || ext == 5) return 0; // XSAVE/XSAVEOPT
                }
                return 0;

                // MOVDIR instructions
            case 0x0F38F8: case 0x0F38F9: // MOVDIRI, MOVDIR64B
                return 0;

            default:
                return 0;
            }
        }

        // 3-byte opcode (0F 38 XX or 0F 3A XX)
        if (opcode_len == 3) {
            uint8_t op2 = opcode_ptr[1];
            uint8_t op3 = opcode_ptr[2];

            // 3DNow! instructions - handled earlier
            if (op1 == 0x0F && op2 == 0x0F) {
                return 0;
            }

            // SSE4.1/4.2 instructions
            if (op2 == 0x38) {
                switch (op3) {
                case 0x00: case 0x01: case 0x02: case 0x03: // PSHUFB/PHADDW/PHADDD/PHADDSW
                case 0x04: case 0x05: case 0x06: case 0x07: // PMADDUBSW/PHSUBW/PHSUBD/PHSUBSW
                case 0x08: case 0x09: case 0x0A: case 0x0B: // PSIGNB/PSIGNW/PSIGND/PMULHRSW
                case 0x0C: case 0x0D: case 0x0E: case 0x0F: // PERMILPS/PERMILPD/PERM2PS/PERM2PD
                case 0x1C: case 0x1D: case 0x1E: case 0x1F: // PABSB/PABSW/PABSD/PMOVSX
                case 0x20: case 0x21: case 0x22: case 0x23: // PMOVSX/PMOVZX
                case 0x30: case 0x31: case 0x32: case 0x33: // PMULDQ/PCMPEQQ/PACKUSDW
                case 0x37: case 0x38: case 0x39: case 0x3A: // PCMPGTQ/PMINSB/PMINSD/PMINUW
                case 0x3B: case 0x3C: case 0x3D: case 0x3E: // PMINUD/PMAXSB/PMAXSD/PMAXUD
                case 0x40: case 0x41: case 0x42: case 0x43: // PMULLD/PHMINPOSUW/PSRLVD/PSRAVD
                case 0x44: case 0x45: case 0x46: case 0x47: // PSLLVD/PCMPESTRM/PCMPESTRI/PCMPISTRM
                case 0x60: case 0x61: case 0x62: case 0x63: // PCMPESTRI/PCMPISTRI/CRC32
                case 0xF0: case 0xF1:                       // MOVBE/CRC32
                case 0xF8: case 0xF9:                       // MOVDIRI, MOVDIR64B
                    return 0;
                    // AVX512-VBMI instructions
                case 0x65: case 0x75: case 0x67: // VPERMB, VPERMI2B, VPERMT2B
                    return 0;
                }
            }
            else if (op2 == 0x3A) {
                switch (op3) {
                case 0x08: case 0x09: case 0x0A: case 0x0B: // ROUNDPS/ROUNDPD/ROUNDSS/ROUNDSD
                case 0x0C: case 0x0D: case 0x0E: case 0x0F: // BLENDPS/BLENDPD/BLENDVPS/BLENDVPD
                case 0x14: case 0x15: case 0x16: case 0x17: // PBLENDW/PALIGNR/PEXTRB/PEXTRW
                case 0x18: case 0x19: case 0x1A: case 0x1B: // PEXTRD/PEXTRQ/EXTRACTPS/INSERTPS
                case 0x20: case 0x21: case 0x22: case 0x23: // PINSRB/INSERTPS/PINSRD/PINSRQ
                case 0x40: case 0x41: case 0x42:             // DPPD/DPPS/MPSADBW
                case 0x60: case 0x61: case 0x62: case 0x63: // PCMPESTRM/PCMPESTRI/PCMPISTRM/PCMPISTRI
                case 0xCC: case 0xCD: case 0xCE: case 0xCF: // VPERMIL2PD/PS
                    return 1; // SSE4.1/4.2 instructions with imm8
                    // AVX512-VBMI2 instructions
                case 0x70: case 0x71: case 0x72: case 0x73: // VPSHRDV, VPSHLDV
                    return 1;
                }
            }

            // AVX512 instructions (only when EVEX prefix is present)
            if (is_evex && (op2 == 0x38 || op2 == 0x3A)) {
                return 1;
            }

            return 0;
        }

        return 0;
    }
};

void run_test(const std::vector<uint8_t>& code, const std::string& name) {
    std::cout << "Testing " << name << " (" << bytes_to_hex(code.data(), code.size()) << "): ";
    try {
        auto len = instruction_decoder::decode_instruction_length(code.data(), code.size());
        std::cout << "OK. Length: " << len.total_len << " bytes\n";
    }
    catch (const std::exception& e) {
        std::cout << "FAILED: " << e.what() << "\n";
    }
}

int main() {
    // 基本指令
    run_test({ 0x90 }, "NOP");
    run_test({ 0xC3 }, "RET");
    run_test({ 0xE9, 0x78, 0x56, 0x34, 0x12 }, "JMP rel32");

    // 64位指令
    run_test({ 0x48, 0x8B, 0x05, 0x78, 0x56, 0x34, 0x12 }, "MOV RAX, [RIP+0x12345678]");
    run_test({ 0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01 }, "MOV RAX, 0x0123456789ABCDEF");

    // 栈操作
    run_test({ 0x60 }, "PUSHA");
    run_test({ 0x61 }, "POPA");
    run_test({ 0x9C }, "PUSHFD");
    run_test({ 0x9D }, "POPFD");
    run_test({ 0x68, 0xEF, 0xBE, 0xAD, 0xDE }, "PUSH 0xDEADBEEF");
    run_test({ 0x6A, 0x2A }, "PUSH 42");

    // 条件跳转
    run_test({ 0x74, 0x12 }, "JE rel8");
    run_test({ 0x0F, 0x84, 0xEF, 0xBE, 0xAD, 0xDE }, "JE rel32");

    // 系统指令
    run_test({ 0x0F, 0x34 }, "SYSENTER");
    run_test({ 0x0F, 0x05 }, "SYSCALL");
    run_test({ 0xCD, 0x80 }, "INT 80h");
    run_test({ 0xCC }, "INT3");
    run_test({ 0xCE }, "INTO");
    run_test({ 0xF4 }, "HLT");

    // MMX 指令 (完整扩展)
    run_test({ 0x0F, 0x6F, 0xC0 }, "MOVQ mm0, mm0");
    run_test({ 0x0F, 0x74, 0xC9 }, "PCMPEQB mm1, mm1");
    run_test({ 0x0F, 0xD4, 0xC0 }, "PADDQ mm0, mm0");
    run_test({ 0x0F, 0xE4, 0xC0 }, "PMULHUW mm0, mm0");
    run_test({ 0x0F, 0x6E, 0xC0 }, "MOVD mm0, eax");
    run_test({ 0x0F, 0xC4, 0xC0, 0x03 }, "PINSRW mm0, eax, 3");
    run_test({ 0x0F, 0xF0, 0xC0 }, "PSHUFLW mm0, mm0, 0");
    run_test({ 0x0F, 0x70, 0xC0, 0x03 }, "PSHUFW mm0, mm0, 3");
    run_test({ 0x0F, 0xDB, 0xC0 }, "PAND mm0, mm0");
    run_test({ 0x0F, 0xDF, 0xC0 }, "PANDN mm0, mm0");
    run_test({ 0x0F, 0xEB, 0xC0 }, "POR mm0, mm0");
    run_test({ 0x0F, 0xEF, 0xC0 }, "PXOR mm0, mm0");
    run_test({ 0x0F, 0xE8, 0xC0 }, "PSUBSB mm0, mm0");
    run_test({ 0x0F, 0xD8, 0xC0 }, "PSUBUSB mm0, mm0");
    run_test({ 0x0F, 0xFC, 0xC0 }, "PADDB mm0, mm0");
    run_test({ 0x0F, 0xEC, 0xC0 }, "PADDSB mm0, mm0");
    run_test({ 0x0F, 0xDC, 0xC0 }, "PADDUSB mm0, mm0");
    run_test({ 0x0F, 0x61, 0xC0 }, "PUNPCKLWD mm0, mm0");
    run_test({ 0x0F, 0x62, 0xC0 }, "PUNPCKLDQ mm0, mm0");
    run_test({ 0x0F, 0x6C, 0xC0 }, "PUNPCKLQDQ mm0, mm0");

    // SSE 指令
    run_test({ 0x66, 0x0F, 0x70, 0xC0, 0x03 }, "PSHUFD xmm0, xmm0, 3");
    run_test({ 0xF3, 0x0F, 0x6F, 0x00 }, "MOVDQU xmm0, [rax]");
    run_test({ 0x0F, 0x10, 0x00 }, "MOVUPS xmm0, [rax]");
    run_test({ 0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x03 }, "PALIGNR xmm0, xmm1, 3");
    run_test({ 0x66, 0x0F, 0x3A, 0x41, 0xC0, 0x01 }, "PHADDW xmm0, xmm0, 1");
    run_test({ 0x66, 0x0F, 0x38, 0x40, 0xC1 }, "PMULLD xmm0, xmm1");
    run_test({ 0x66, 0x0F, 0x73, 0xD0, 0x02 }, "PSRLDQ xmm0, 2");
    run_test({ 0xF2, 0x0F, 0x12, 0xC0 }, "MOVDDUP xmm0, xmm0");

    // SSE4
    run_test({ 0x66, 0x0F, 0x3A, 0x17, 0xC0, 0x02 }, "PEXTRD eax, xmm0, 2");
    run_test({ 0x66, 0x0F, 0x3A, 0x22, 0xC0, 0x04 }, "PINSRD xmm0, eax, 4");

    // AES
    run_test({ 0x66, 0x0F, 0x38, 0xDC, 0xD1 }, "AESENC xmm2, xmm1");
    run_test({ 0x66, 0x0F, 0x38, 0xDD, 0xD1 }, "AESENCLAST xmm2, xmm1");
    run_test({ 0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x01 }, "AESKEYGENASSIST xmm2, xmm1, 1");

    // SHA
    run_test({ 0x0F, 0x38, 0xC8, 0xD1 }, "SHA1NEXTE xmm2, xmm1");
    run_test({ 0x0F, 0x38, 0xC9, 0xD1 }, "SHA1MSG1 xmm2, xmm1");
    run_test({ 0x0F, 0x38, 0xCA, 0xD1 }, "SHA1MSG2 xmm2, xmm1");
    run_test({ 0x0F, 0x38, 0xCB, 0xD1 }, "SHA256RNDS2 xmm2, xmm1");

    // AVX
    run_test({ 0xC5, 0xF8, 0x58, 0xC0 }, "VADDPS xmm0, xmm1, xmm0");
    run_test({ 0xC4, 0xE3, 0x7D, 0x19, 0x45, 0x00, 0x04 }, "VEXTRACTF32x4 [rbp+0], ymm0, 4");
    run_test({ 0xC5, 0xFC, 0x58, 0xC0 }, "VADDPS ymm0, ymm1, ymm0");

    // AVX2
    run_test({ 0xC4, 0xE2, 0x7D, 0x58, 0xC0 }, "VPBROADCASTD ymm0, xmm0");
    run_test({ 0xC4, 0xE2, 0x7D, 0x59, 0xC0 }, "VPBROADCASTQ ymm0, xmm0");
    run_test({ 0xC4, 0xE2, 0x7D, 0x47, 0xC0 }, "VPSLLVD ymm0, ymm1, ymm0");

    // AVX512
    run_test({ 0x62, 0xF1, 0x7C, 0x08, 0x58, 0xC0 }, "VADDPS xmm0, xmm1, xmm0");
    run_test({ 0x62, 0xF3, 0x7D, 0x08, 0x1F, 0xC0, 0x04 }, "VCMPPS k0, ymm0, ymm0, 4");
    run_test({ 0x62, 0xF1, 0xFD, 0x08, 0x6F, 0x00 }, "VMOVDQA64 zmm0, [rax]");
    run_test({ 0x62, 0xF1, 0x7D, 0x48, 0x6F, 0x00 }, "VMOVDQA32 zmm0, [rax]");
    run_test({ 0x62, 0xF1, 0xFD, 0x48, 0x6F, 0x00 }, "VMOVDQA64 zmm0, [rax]");
    run_test({ 0x62, 0xF3, 0x7D, 0x48, 0x1F, 0xC0, 0x04 }, "VCMPPS k0, zmm0, zmm0, 4");
    run_test({ 0x62, 0xF3, 0x7D, 0x48, 0x33, 0xC0, 0x01 }, "VPALIGNR zmm0, zmm1, zmm0, 1");
    run_test({ 0x62, 0xF2, 0x7D, 0x48, 0x65, 0xC0 }, "VPERMB zmm0, zmm1, zmm0");
    run_test({ 0x62, 0xF2, 0x7D, 0x48, 0x75, 0xC0 }, "VPERMI2B zmm0, zmm1, zmm0");
    run_test({ 0x62, 0xF2, 0x7D, 0x48, 0x67, 0xC0 }, "VPERMT2B zmm0, zmm1, zmm0");
    run_test({ 0x62, 0xF3, 0x7D, 0x48, 0x71, 0xC0, 0x01 }, "VPSHLDV zmm0, zmm1, zmm0, 1");
    run_test({ 0x62, 0xF3, 0x7D, 0x48, 0x73, 0xC0, 0x01 }, "VPSHRDV zmm0, zmm1, zmm0, 1");

    // FMA
    run_test({ 0xC4, 0xE2, 0xF1, 0xB8, 0xC1 }, "VFMADD231PD xmm0, xmm1, xmm1");
    run_test({ 0xC4, 0xE2, 0xF1, 0x98, 0xC1 }, "VFMSUB132PD xmm0, xmm1, xmm1");
    run_test({ 0xC4, 0xE2, 0xF5, 0xB8, 0xC1 }, "VFMADD231PD ymm0, ymm1, ymm1");

    // 3DNow! 
    run_test({ 0x0F, 0x0F, 0xC0, 0x9E }, "PFACC mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0x86 }, "PFADD mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0x8A }, "PFNACC mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0x8E }, "PFPNACC mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0x96 }, "PFCMPGE mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0x97 }, "PFMIN mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0x9A }, "PFRCP mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0x9C }, "PFRCPIT1 mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0xA0 }, "PFCMPEQ mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0xA6 }, "PFRSQRT mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0xA7 }, "PFRSQIT1 mm0, mm0");
    run_test({ 0x0F, 0x0F, 0xC0, 0xAE }, "PFRCPIT2 mm0, mm0");

    // XOP 指令 (完整扩展)
    run_test({ 0x8F, 0xE8, 0x78, 0x80, 0xC0 }, "VPERMIL2PD xmm0, xmm1, xmm0, xmm0, 0");
    run_test({ 0x8F, 0xE8, 0x79, 0x00, 0xC0 }, "VPPERM xmm0, xmm1, xmm0, xmm0");
    run_test({ 0x8F, 0xE8, 0x7A, 0x80, 0xC0 }, "VPCMOV xmm0, xmm1, xmm0, xmm0");
    run_test({ 0x8F, 0xE8, 0x78, 0x81, 0xC0 }, "VPERMIL2PS xmm0, xmm1, xmm0, xmm0, 1");
    run_test({ 0x8F, 0xE8, 0x79, 0x01, 0xC0 }, "VPPERM xmm0, xmm1, xmm0, 1");
    run_test({ 0x8F, 0xE8, 0x7A, 0x81, 0xC0 }, "VPCMOV xmm0, xmm1, xmm0, xmm0, 1");
    run_test({ 0x8F, 0xE8, 0x7A, 0x82, 0xC0 }, "VPCMOV xmm0, xmm1, xmm0, xmm0, 2");
    run_test({ 0x8F, 0xE8, 0x7A, 0x83, 0xC0 }, "VPCMOV xmm0, xmm1, xmm0, xmm0, 3");
    run_test({ 0x8F, 0xE8, 0x7A, 0x84, 0xC0 }, "VPCMOV xmm0, xmm1, xmm0, xmm0, 4");
    run_test({ 0x8F, 0xE8, 0x7A, 0x85, 0xC0 }, "VPCMOV xmm0, xmm1, xmm0, xmm0, 5");
    run_test({ 0x8F, 0xE8, 0x78, 0x86, 0xC0 }, "VPERMIL2PD xmm0, xmm1, xmm0, xmm0, 6");
    run_test({ 0x8F, 0xE8, 0x78, 0x87, 0xC0 }, "VPERMIL2PD xmm0, xmm1, xmm0, xmm0, 7");
    run_test({ 0x8F, 0xE8, 0x7A, 0x86, 0xC0 }, "VPCMOV xmm0, xmm1, xmm0, xmm0, 6");
    run_test({ 0x8F, 0xE8, 0x7A, 0x87, 0xC0 }, "VPCMOV xmm0, xmm1, xmm0, xmm0, 7");

    // FPU 指令
    run_test({ 0xD8, 0xC0 }, "FADD ST(0), ST(0)");
    run_test({ 0xD9, 0xEE }, "FLDZ");
    run_test({ 0xDB, 0xE8 }, "FLDL2T");
    run_test({ 0xD8, 0x86, 0x78, 0x56, 0x34, 0x12 }, "FADD dword [esi+0x12345678]");
    run_test({ 0xDF, 0x85, 0x78, 0x56, 0x34, 0x12 }, "FILD word [ebp+0x12345678]");
    run_test({ 0xDF, 0xAD, 0x78, 0x56, 0x34, 0x12 }, "FILD qword [ebp+0x12345678]");
    run_test({ 0xDD, 0x85, 0x78, 0x56, 0x34, 0x12 }, "FLD qword [ebp+0x12345678]");
    run_test({ 0xD9, 0x85, 0x78, 0x56, 0x34, 0x12 }, "FLD dword [ebp+0x12345678]");
    run_test({ 0xDE, 0xC1 }, "FADDP ST(1), ST(0)");
    run_test({ 0xDA, 0x08 }, "FIADD dword [eax]");
    run_test({ 0xD8, 0xD9 }, "FCOM ST(1)");
    run_test({ 0xD9, 0xE0 }, "FCHS");
    run_test({ 0xDA, 0x30 }, "FICOMP word [eax]");

    // VMX 虚拟机指令
    run_test({ 0x0F, 0x01, 0xC1 }, "VMCALL");
    run_test({ 0x0F, 0x01, 0xC2 }, "VMLAUNCH");
    run_test({ 0x0F, 0x01, 0xC3 }, "VMRESUME");
    run_test({ 0x0F, 0x01, 0xC4 }, "VMXOFF");
    run_test({ 0xF3, 0x0F, 0xC7, 0x10 }, "VMXON [rax]");
    run_test({ 0x0F, 0x01, 0xC7 }, "VMXON [rdi]");
    run_test({ 0x0F, 0x01, 0xCC }, "VMWRITE");
    run_test({ 0x0F, 0x01, 0xCD }, "VMCLEAR [rbp]");
    run_test({ 0x0F, 0x01, 0xCE }, "VMXON [rsi]");
    run_test({ 0x0F, 0x01, 0xCF }, "VMPTRST [rdi]");
    run_test({ 0x0F, 0x01, 0xD9 }, "VMPTRLD [rcx]");
    run_test({ 0x0F, 0x01, 0xDA }, "VMCLEAR [rdx]");
    run_test({ 0x0F, 0x01, 0xDB }, "VMREAD");
    run_test({ 0x0F, 0x01, 0xDC }, "VMWRITE");
    run_test({ 0x0F, 0x01, 0xDD }, "VMREAD [rbp]");
    run_test({ 0x0F, 0x01, 0xDE }, "VMWRITE [rsi]");

    // 特殊指令
    run_test({ 0xF1 }, "INT1");
    run_test({ 0x0F, 0xA0 }, "PUSH FS");
    run_test({ 0x0F, 0xA1 }, "POP FS");
    run_test({ 0x0F, 0x00, 0xC0 }, "SLDT EAX");
    run_test({ 0x0F, 0x00, 0xD0 }, "LLDT EAX");
    run_test({ 0x0F, 0x00, 0xE0 }, "LTR EAX");
    run_test({ 0x0F, 0x01, 0xC8 }, "MONITOR");
    run_test({ 0x0F, 0x01, 0xD0 }, "XGETBV");
    run_test({ 0x0F, 0x01, 0xD8 }, "XSETBV");
    run_test({ 0x0F, 0x01, 0xE0 }, "VMRUN");
    run_test({ 0x0F, 0x01, 0xE1 }, "VMMCALL");
    run_test({ 0x0F, 0x01, 0xE2 }, "VMLOAD");
    run_test({ 0x0F, 0x01, 0xE3 }, "VMSAVE");
    run_test({ 0x0F, 0x01, 0xE8 }, "INVEPT");
    run_test({ 0x0F, 0x01, 0xE9 }, "INVVPID");

    // 新增测试用例
    run_test({ 0x0F, 0x01, 0x00 }, "SGDT [eax]");
    run_test({ 0x0F, 0x01, 0x08 }, "SIDT [eax]");
    run_test({ 0x0F, 0x01, 0x10 }, "LGDT [eax]");
    run_test({ 0x0F, 0x01, 0x18 }, "LIDT [eax]");
    run_test({ 0x0F, 0x01, 0x20 }, "SMSW [eax]");
    run_test({ 0x0F, 0x01, 0x30 }, "LMSW [eax]");
    run_test({ 0x0F, 0x20, 0xC0 }, "MOV EAX, CR0");
    run_test({ 0x0F, 0x20, 0xD8 }, "MOV EAX, CR3");
    run_test({ 0x0F, 0x21, 0xC0 }, "MOV EAX, DR0");
    run_test({ 0x0F, 0x21, 0xD8 }, "MOV EAX, DR3");
    run_test({ 0x0F, 0x01, 0xF0 }, "VMXON [eax]");
    run_test({ 0x0F, 0x01, 0xF8 }, "SWAPGS");
    run_test({ 0x0F, 0xAE, 0x00 }, "FXSAVE [eax]");
    run_test({ 0x0F, 0xAE, 0x08 }, "FXRSTOR [eax]");
    run_test({ 0x0F, 0x31 }, "RDTSC");
    run_test({ 0x0F, 0x01, 0xF9 }, "RDTSCP");
    run_test({ 0x0F, 0x32 }, "RDMSR");
    run_test({ 0x0F, 0x30 }, "WRMSR");
    run_test({ 0x0F, 0x38, 0xF0, 0xC0 }, "MOVBE EAX, EAX");
    run_test({ 0x0F, 0x38, 0xF1, 0x00 }, "MOVBE [eax], EAX");
    run_test({ 0xC4, 0xE2, 0x79, 0x17, 0xC0 }, "VPTEST xmm0, xmm0");
    run_test({ 0xC4, 0xE2, 0x7D, 0x17, 0xC0 }, "VPTEST ymm0, ymm0");
    run_test({ 0x62, 0xF1, 0x7D, 0x48, 0x54, 0xC0 }, "VANDPS zmm0, zmm0, zmm0");
    run_test({ 0x62, 0xF1, 0x7D, 0x48, 0x55, 0xC0 }, "VANDNPS zmm0, zmm0, zmm0");
    run_test({ 0x62, 0xF1, 0x7D, 0x48, 0x56, 0xC0 }, "VORPS zmm0, zmm0, zmm0");
    run_test({ 0x62, 0xF1, 0x7D, 0x48, 0x57, 0xC0 }, "VXORPS zmm0, zmm0, zmm0");
    run_test({ 0x0F, 0x01, 0xEC }, "CLUI");
    run_test({ 0x0F, 0x01, 0xED }, "STUI");
    run_test({ 0x0F, 0x01, 0xCF }, "CLDEMOTE [rdi]");
    run_test({ 0x0F, 0x01, 0xEA }, "UIRET");
    run_test({ 0x0F, 0x18, 0x00 }, "PREFETCHNTA [eax]");
    run_test({ 0x0F, 0x18, 0x08 }, "PREFETCHT0 [eax]");
    run_test({ 0x0F, 0x18, 0x10 }, "PREFETCHT1 [eax]");
    run_test({ 0x0F, 0x18, 0x18 }, "PREFETCHT2 [eax]");
    run_test({ 0x0F, 0x18, 0x20 }, "PREFETCHNTA [eax]");
    run_test({ 0x0F, 0xAE, 0x30 }, "XSAVEOPT [eax]");
    run_test({ 0x0F, 0x01, 0xEE }, "SENDUIPI");
    run_test({ 0x0F, 0x01, 0xD9 }, "UD1");
    run_test({ 0x0F, 0x08 }, "INVD");
    run_test({ 0x0F, 0x09 }, "WBINVD");
    run_test({ 0x0F, 0x01, 0xFC }, "CLZERO");
    run_test({ 0x48, 0x8B, 0x84, 0xD5, 0x00, 0x11, 0x00, 0x00 }, "MOV RAX, [RBP+RDX*8+0x1100]");
    run_test({ 0xC5, 0xFE, 0x6F, 0x84, 0xD5, 0x00, 0x11, 0x00, 0x00 }, "VMOVDQU ymm0, [RBP+RDX*8+0x1100]");
    run_test({ 0x62, 0xF1, 0xFE, 0x48, 0x6F, 0x84, 0xD5, 0x00, 0x11, 0x00, 0x00 }, "VMOVDQU64 zmm0, [RBP+RDX*8+0x1100]");

    // 边界测试
    try {
        std::vector<uint8_t> incomplete = { 0x0F, 0x38 };
        std::cout << "Testing incomplete instruction (0F 38): ";
        auto len = instruction_decoder::decode_instruction_length(incomplete.data(), incomplete.size());
        std::cout << "FAILED: Should throw exception\n";
    }
    catch (const std::exception& e) {
        std::cout << "OK: " << e.what() << "\n";
    }

    try {
        std::vector<uint8_t> incomplete_vex = { 0xC4, 0xE2 };
        std::cout << "Testing incomplete VEX prefix (C4 E2): ";
        auto len = instruction_decoder::decode_instruction_length(incomplete_vex.data(), incomplete_vex.size());
        std::cout << "FAILED: Should throw exception\n";
    }
    catch (const std::exception& e) {
        std::cout << "OK: " << e.what() << "\n";
    }

    try {
        std::vector<uint8_t> incomplete_evex = { 0x62, 0xF1, 0x7D };
        std::cout << "Testing incomplete EVEX prefix (62 F1 7D): ";
        auto len = instruction_decoder::decode_instruction_length(incomplete_evex.data(), incomplete_evex.size());
        std::cout << "FAILED: Should throw exception\n";
    }
    catch (const std::exception& e) {
        std::cout << "OK: " << e.what() << "\n";
    }

    return 0;
}