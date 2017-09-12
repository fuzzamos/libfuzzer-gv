//===- FuzzerTracePC.h - Internal header for the Fuzzer ---------*- C++ -* ===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// fuzzer::TracePC
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_TRACE_PC
#define LLVM_FUZZER_TRACE_PC

#include "FuzzerDefs.h"
#include "FuzzerDictionary.h"
#include "FuzzerValueBitMap.h"

#include <set>
#include <map>

namespace fuzzer {

// TableOfRecentCompares (TORC) remembers the most recently performed
// comparisons of type T.
// We record the arguments of CMP instructions in this table unconditionally
// because it seems cheaper this way than to compute some expensive
// conditions inside __sanitizer_cov_trace_cmp*.
// After the unit has been executed we may decide to use the contents of
// this table to populate a Dictionary.
template<class T, size_t kSizeT>
struct TableOfRecentCompares {
  static const size_t kSize = kSizeT;
  struct Pair {
    T A, B;
  };
  ATTRIBUTE_NO_SANITIZE_ALL
  void Insert(size_t Idx, const T &Arg1, const T &Arg2) {
    Idx = Idx % kSize;
    Table[Idx].A = Arg1;
    Table[Idx].B = Arg2;
  }

  Pair Get(size_t I) { return Table[I % kSize]; }

  Pair Table[kSize];
};

class CustomValue {
    size_t MaxVal;

    public:
    CustomValue(void) :
        MaxVal(0) {}

    void Update(size_t newval) {
        if ( newval > MaxVal ) {
            printf("update from %zu to %zu\n", MaxVal, newval);
            MaxVal = newval;
        }
    }

    size_t GetMax(void) const {
        return MaxVal;
    }
};

class TracePC {
 public:
  static const size_t kNumPCs = 1 << 21;
  // How many bits of PC are used from __sanitizer_cov_trace_pc.
  static const size_t kTracePcBits = 18;

  void HandleInit(uint32_t *Start, uint32_t *Stop);
  void HandleInline8bitCountersInit(uint8_t *Start, uint8_t *Stop);
  void HandleCallerCallee(uintptr_t Caller, uintptr_t Callee);
  template <class T> void HandleCmp(uintptr_t PC, T Arg1, T Arg2);
  size_t GetTotalPCCoverage();
  const size_t GetStackDepthRecord() const;
  const size_t GetCodeIntensity() const;
  void ResetCodeIntensity();
  void UpdateCodeIntensityRecord(size_t ci) {
      if (ci > codeIntensityRecord) {
          codeIntensityRecord = ci;
      }
  }
  size_t GetCodeIntensityRecord() { return codeIntensityRecord; }
  void UpdateAllocRecord(size_t _allocRecord) {
      allocRecord = _allocRecord;
  }
  void UpdateCustomValues(std::vector<std::pair<size_t, size_t>> *customValues) {
      for ( auto &curVal : *customValues ) {
          CustomValue cv;
          localCustomValues.insert(
                  std::pair<size_t, CustomValue>(curVal.first, cv) );
          localCustomValues[curVal.first].Update(curVal.second);
      }

  }
  void UpdateCustomRecord(int Res) {
      if (Res < 0) {
          return;
      }
      if (Res > customRecord) {
          customRecord = (size_t)Res;
      }
  }
  size_t GetCustomRecord() { return customRecord; }
  void SetUseCounters(bool UC) { UseCounters = UC; }
  void SetUseValueProfile(bool VP) { UseValueProfile = VP; }
  void SetStackDepthGuided(bool SD) { StackDepthGuided = SD; }
  void SetIntensityGuided(bool I) { IntensityGuided = I; }
  void SetAllocGuided(bool A) { AllocGuided = A; }
  void SetCustomGuided(bool I) { CustomGuided = I; }
  void SetCustomFuncGuided(bool C) { CustomFuncGuided = C; }
  bool IsCustomFuncGuided(void) { return CustomFuncGuided;}
  void SetNoCoverageGuided(bool C) { NoCoverageGuided = C; }
  void SetPrintNewPCs(bool P) { DoPrintNewPCs = P; }
  template <class Callback> void CollectFeatures(Callback CB) const;

  void ResetMaps() {
    ValueProfileMap.Reset();
    memset(Counters(), 0, GetNumPCs());
    ClearExtraCounters();
    ResetCodeIntensity();
  }

  void UpdateFeatureSet(size_t CurrentElementIdx, size_t CurrentElementSize);
  void PrintFeatureSet();

  void PrintModuleInfo();

  void PrintCoverage();
  void DumpCoverage();

  void AddValueForMemcmp(void *caller_pc, const void *s1, const void *s2,
                         size_t n, bool StopAtZero);

  TableOfRecentCompares<uint32_t, 32> TORC4;
  TableOfRecentCompares<uint64_t, 32> TORC8;
  TableOfRecentCompares<Word, 32> TORCW;

  void PrintNewPCs();
  void InitializePrintNewPCs();
  size_t GetNumPCs() const {
    return NumGuards == 0 ? (1 << kTracePcBits) : Min(kNumPCs, NumGuards + 1);
  }
  uintptr_t GetPC(size_t Idx) {
    assert(Idx < GetNumPCs());
    return PCs()[Idx];
  }

private:
  bool UseCounters = false;
  bool UseValueProfile = false;
  bool StackDepthGuided = false;
  bool IntensityGuided = false;
  bool AllocGuided = false;
  bool CustomGuided = false;
  bool CustomFuncGuided = false;
  bool NoCoverageGuided = false;
  bool DoPrintNewPCs = false;

  struct Module {
    uint32_t *Start, *Stop;
  };

  Module Modules[4096];
  size_t NumModules;  // linker-initialized.
  size_t NumGuards;  // linker-initialized.

  struct { uint8_t *Start, *Stop; } ModuleCounters[4096];
  size_t NumModulesWithInline8bitCounters;  // linker-initialized.
  size_t NumInline8bitCounters;

  uint8_t *Counters() const;
  uintptr_t *PCs() const;

  std::set<uintptr_t> *PrintedPCs;

  ValueBitMap ValueProfileMap;
  size_t codeIntensityRecord;
  size_t allocRecord = 0;
  size_t customRecord;
  std::map<size_t, CustomValue> localCustomValues;
};

template <class Callback> // void Callback(size_t Idx, uint8_t Value);
ATTRIBUTE_NO_SANITIZE_ALL
void ForEachNonZeroByte(const uint8_t *Begin, const uint8_t *End,
                        size_t FirstFeature, Callback Handle8bitCounter) {
  typedef uintptr_t LargeType;
  const size_t Step = sizeof(LargeType) / sizeof(uint8_t);
  const size_t StepMask = Step - 1;
  auto P = Begin;
  // Iterate by 1 byte until either the alignment boundary or the end.
  for (; reinterpret_cast<uintptr_t>(P) & StepMask && P < End; P++)
    if (uint8_t V = *P)
      Handle8bitCounter(FirstFeature + P - Begin, V);

  // Iterate by Step bytes at a time.
  for (; P < End; P += Step)
    if (LargeType Bundle = *reinterpret_cast<const LargeType *>(P))
      for (size_t I = 0; I < Step; I++, Bundle >>= 8)
        if (uint8_t V = Bundle & 0xff)
          Handle8bitCounter(FirstFeature + P - Begin + I, V);

  // Iterate by 1 byte until the end.
  for (; P < End; P++)
    if (uint8_t V = *P)
      Handle8bitCounter(FirstFeature + P - Begin, V);
}

template <class Callback>  // bool Callback(size_t Feature)
ATTRIBUTE_NO_SANITIZE_ALL
__attribute__((noinline))
void TracePC::CollectFeatures(Callback HandleFeature) const {
        uint8_t *Counters = this->Counters();
        size_t N = GetNumPCs();
    if (NoCoverageGuided == false) {
        auto Handle8bitCounter = [&](size_t Idx, uint8_t Counter) {
            assert(Counter);
            unsigned Bit = 0;
            /**/ if (Counter >= 128) Bit = 7;
            else if (Counter >= 32) Bit = 6;
            else if (Counter >= 16) Bit = 5;
            else if (Counter >= 8) Bit = 4;
            else if (Counter >= 4) Bit = 3;
            else if (Counter >= 3) Bit = 2;
            else if (Counter >= 2) Bit = 1;
            HandleFeature(Idx * 8 + Bit);
        };

        size_t FirstFeature = 0;
        ForEachNonZeroByte(Counters, Counters + N, FirstFeature, Handle8bitCounter);
        FirstFeature += N * 8;
        for (size_t i = 0; i < NumModulesWithInline8bitCounters; i++) {
            ForEachNonZeroByte(ModuleCounters[i].Start, ModuleCounters[i].Stop,
                    FirstFeature, Handle8bitCounter);
            FirstFeature += 8 * (ModuleCounters[i].Stop - ModuleCounters[i].Start);
        }

        ForEachNonZeroByte(ExtraCountersBegin(), ExtraCountersEnd(), FirstFeature,
                Handle8bitCounter);
    }
  if (UseValueProfile)
    ValueProfileMap.ForEach([&](size_t Idx) {
      HandleFeature(N * 8 + Idx);
    });

  if (StackDepthGuided) {
      HandleFeature(GetStackDepthRecord());
  }

  if (IntensityGuided) {
      HandleFeature(codeIntensityRecord);
  }

  if (AllocGuided) {
      HandleFeature(allocRecord);
  }

  if (CustomGuided) {
      HandleFeature(customRecord);
  }

  if (CustomFuncGuided) {
      for (auto &curVal : localCustomValues) {
          HandleFeature( curVal.second.GetMax() );
      }
  }
}

extern TracePC TPC;

}  // namespace fuzzer

#endif  // LLVM_FUZZER_TRACE_PC
