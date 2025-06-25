; ModuleID = 'ubcms.bpf.c'
source_filename = "ubcms.bpf.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%struct.anon = type { ptr, ptr, ptr, ptr }
%struct.pkt_5tuple = type <{ i32, i32, i16, i16, i8 }>
%struct.xdp_md = type { i32, i32, i32, i32, i32, i32 }
%struct.t_meta = type { i16, i16, i16, i16 }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }
%struct.iphdr = type { i8, i8, i16, i16, i16, i8, i8, i16, %union.anon }
%union.anon = type { %struct.anon.0 }
%struct.anon.0 = type { i32, i32 }
%struct.tcphdr = type { i16, i16, i32, i32, i16, i16, i16, i16 }
%struct.udphdr = type { i16, i16, i16, i16 }

@ubcms.____fmt = internal constant [15 x i8] c"md + 1 > data\0A\00", align 1
@bpf_trace_printk = internal global ptr inttoptr (i64 6 to ptr), align 8
@bpf_map_lookup_elem = internal global ptr inttoptr (i64 1 to ptr), align 8
@countmin = dso_local global %struct.anon zeroinitializer, section ".maps", align 8
@ubcms.____fmt.1 = internal constant [11 x i8] c"valid: %d\0A\00", align 1
@ubcms.___fmt = internal constant [19 x i8] c"lens: %d %d %d %d\0A\00", align 1
@bpf_trace_vprintk = internal global ptr inttoptr (i64 177 to ptr), align 8
@ubcms.____fmt.2 = internal constant [27 x i8] c"handle_pkt failed at i %d\0A\00", align 1
@ubcms.____fmt.3 = internal constant [29 x i8] c"len %d lens[i]%d, lentot %d\0A\00", align 1
@LICENSE = dso_local global [13 x i8] c"Dual BSD/GPL\00", section "license", align 1
@handle_pkt.____fmt = internal constant [21 x i8] c"eth + 1 >= data_end\0A\00", align 1
@handle_pkt.____fmt.4 = internal constant [5 x i8] c"eth\0A\00", align 1
@handle_pkt.____fmt.5 = internal constant [13 x i8] c"h_proto: %d\0A\00", align 1
@handle_pkt.____fmt.6 = internal constant [5 x i8] c"udp\0A\00", align 1
@handle_pkt.____fmt.7 = internal constant [7 x i8] c"proto\0A\00", align 1
@llvm.compiler.used = appending global [3 x ptr] [ptr @ubcms, ptr @LICENSE, ptr @countmin], section "llvm.metadata"

; Function Attrs: noinline nounwind optnone
define dso_local i32 @ubcms(ptr noundef %0) #0 section "xdp" {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  %5 = alloca i32, align 4
  %6 = alloca ptr, align 8
  %7 = alloca i64, align 8
  %8 = alloca ptr, align 8
  %9 = alloca i64, align 8
  %10 = alloca i32, align 4
  %11 = alloca ptr, align 8
  %12 = alloca ptr, align 8
  %13 = alloca ptr, align 8
  %14 = alloca ptr, align 8
  %15 = alloca i64, align 8
  %16 = alloca i16, align 2
  %17 = alloca i64, align 8
  %18 = alloca i64, align 8
  %19 = alloca ptr, align 8
  %20 = alloca ptr, align 8
  %21 = alloca ptr, align 8
  %22 = alloca i64, align 8
  %23 = alloca i64, align 8
  %24 = alloca i32, align 4
  %25 = alloca ptr, align 8
  %26 = alloca ptr, align 8
  %27 = alloca ptr, align 8
  %28 = alloca ptr, align 8
  %29 = alloca ptr, align 8
  %30 = alloca i64, align 8
  %31 = alloca i16, align 2
  %32 = alloca [4 x i16], align 2
  %33 = alloca i32, align 4
  %34 = alloca ptr, align 8
  %35 = alloca i32, align 4
  %36 = alloca %struct.pkt_5tuple, align 1
  %37 = alloca [4 x i16], align 2
  %38 = alloca i32, align 4
  %39 = alloca i64, align 8
  %40 = alloca [4 x i64], align 8
  %41 = alloca i64, align 8
  %42 = alloca i64, align 8
  %43 = alloca i64, align 8
  store ptr %0, ptr %25, align 8
  %44 = load ptr, ptr %25, align 8
  %45 = getelementptr inbounds %struct.xdp_md, ptr %44, i32 0, i32 1
  %46 = load i32, ptr %45, align 4
  %47 = zext i32 %46 to i64
  %48 = inttoptr i64 %47 to ptr
  store ptr %48, ptr %26, align 8
  %49 = load ptr, ptr %25, align 8
  %50 = getelementptr inbounds %struct.xdp_md, ptr %49, i32 0, i32 0
  %51 = load i32, ptr %50, align 4
  %52 = zext i32 %51 to i64
  %53 = inttoptr i64 %52 to ptr
  store ptr %53, ptr %27, align 8
  %54 = load ptr, ptr %25, align 8
  %55 = getelementptr inbounds %struct.xdp_md, ptr %54, i32 0, i32 2
  %56 = load i32, ptr %55, align 4
  %57 = zext i32 %56 to i64
  %58 = inttoptr i64 %57 to ptr
  store ptr %58, ptr %28, align 8
  %59 = load ptr, ptr %28, align 8
  store ptr %59, ptr %29, align 8
  %60 = load ptr, ptr %29, align 8
  %61 = getelementptr inbounds %struct.t_meta, ptr %60, i64 1
  %62 = load ptr, ptr %27, align 8
  %63 = icmp ugt ptr %61, %62
  br i1 %63, label %64, label %68

64:                                               ; preds = %1
  %65 = load ptr, ptr @bpf_trace_printk, align 8
  %66 = call i64 (ptr, i32, ...) %65(ptr noundef @ubcms.____fmt, i32 noundef 15)
  store i64 %66, ptr %30, align 8
  %67 = load i64, ptr %30, align 8
  store i32 4369, ptr %24, align 4
  br label %452

68:                                               ; preds = %1
  store i16 0, ptr %31, align 2
  %69 = getelementptr inbounds [4 x i16], ptr %32, i64 0, i64 0
  %70 = load ptr, ptr %29, align 8
  %71 = getelementptr inbounds %struct.t_meta, ptr %70, i32 0, i32 1
  %72 = load i16, ptr %71, align 2
  %73 = call i1 @llvm.is.constant.i16(i16 %72)
  br i1 %73, label %74, label %92

74:                                               ; preds = %68
  %75 = load ptr, ptr %29, align 8
  %76 = getelementptr inbounds %struct.t_meta, ptr %75, i32 0, i32 1
  %77 = load i16, ptr %76, align 2
  %78 = zext i16 %77 to i32
  %79 = shl i32 %78, 8
  %80 = ashr i32 %79, 8
  %81 = shl i32 %80, 8
  %82 = load ptr, ptr %29, align 8
  %83 = getelementptr inbounds %struct.t_meta, ptr %82, i32 0, i32 1
  %84 = load i16, ptr %83, align 2
  %85 = zext i16 %84 to i32
  %86 = shl i32 %85, 0
  %87 = ashr i32 %86, 8
  %88 = shl i32 %87, 0
  %89 = or i32 %81, %88
  %90 = trunc i32 %89 to i16
  %91 = zext i16 %90 to i32
  br label %98

92:                                               ; preds = %68
  %93 = load ptr, ptr %29, align 8
  %94 = getelementptr inbounds %struct.t_meta, ptr %93, i32 0, i32 1
  %95 = load i16, ptr %94, align 2
  %96 = call i16 @llvm.bswap.i16(i16 %95)
  %97 = zext i16 %96 to i32
  br label %98

98:                                               ; preds = %92, %74
  %99 = phi i32 [ %91, %74 ], [ %97, %92 ]
  %100 = trunc i32 %99 to i16
  store i16 %100, ptr %69, align 2
  %101 = getelementptr inbounds i16, ptr %69, i64 1
  %102 = load ptr, ptr %29, align 8
  %103 = getelementptr inbounds %struct.t_meta, ptr %102, i32 0, i32 2
  %104 = load i16, ptr %103, align 2
  %105 = call i1 @llvm.is.constant.i16(i16 %104)
  br i1 %105, label %106, label %124

106:                                              ; preds = %98
  %107 = load ptr, ptr %29, align 8
  %108 = getelementptr inbounds %struct.t_meta, ptr %107, i32 0, i32 2
  %109 = load i16, ptr %108, align 2
  %110 = zext i16 %109 to i32
  %111 = shl i32 %110, 8
  %112 = ashr i32 %111, 8
  %113 = shl i32 %112, 8
  %114 = load ptr, ptr %29, align 8
  %115 = getelementptr inbounds %struct.t_meta, ptr %114, i32 0, i32 2
  %116 = load i16, ptr %115, align 2
  %117 = zext i16 %116 to i32
  %118 = shl i32 %117, 0
  %119 = ashr i32 %118, 8
  %120 = shl i32 %119, 0
  %121 = or i32 %113, %120
  %122 = trunc i32 %121 to i16
  %123 = zext i16 %122 to i32
  br label %130

124:                                              ; preds = %98
  %125 = load ptr, ptr %29, align 8
  %126 = getelementptr inbounds %struct.t_meta, ptr %125, i32 0, i32 2
  %127 = load i16, ptr %126, align 2
  %128 = call i16 @llvm.bswap.i16(i16 %127)
  %129 = zext i16 %128 to i32
  br label %130

130:                                              ; preds = %124, %106
  %131 = phi i32 [ %123, %106 ], [ %129, %124 ]
  %132 = trunc i32 %131 to i16
  store i16 %132, ptr %101, align 2
  %133 = getelementptr inbounds i16, ptr %101, i64 1
  %134 = load ptr, ptr %29, align 8
  %135 = getelementptr inbounds %struct.t_meta, ptr %134, i32 0, i32 3
  %136 = load i16, ptr %135, align 2
  %137 = call i1 @llvm.is.constant.i16(i16 %136)
  br i1 %137, label %138, label %156

138:                                              ; preds = %130
  %139 = load ptr, ptr %29, align 8
  %140 = getelementptr inbounds %struct.t_meta, ptr %139, i32 0, i32 3
  %141 = load i16, ptr %140, align 2
  %142 = zext i16 %141 to i32
  %143 = shl i32 %142, 8
  %144 = ashr i32 %143, 8
  %145 = shl i32 %144, 8
  %146 = load ptr, ptr %29, align 8
  %147 = getelementptr inbounds %struct.t_meta, ptr %146, i32 0, i32 3
  %148 = load i16, ptr %147, align 2
  %149 = zext i16 %148 to i32
  %150 = shl i32 %149, 0
  %151 = ashr i32 %150, 8
  %152 = shl i32 %151, 0
  %153 = or i32 %145, %152
  %154 = trunc i32 %153 to i16
  %155 = zext i16 %154 to i32
  br label %162

156:                                              ; preds = %130
  %157 = load ptr, ptr %29, align 8
  %158 = getelementptr inbounds %struct.t_meta, ptr %157, i32 0, i32 3
  %159 = load i16, ptr %158, align 2
  %160 = call i16 @llvm.bswap.i16(i16 %159)
  %161 = zext i16 %160 to i32
  br label %162

162:                                              ; preds = %156, %138
  %163 = phi i32 [ %155, %138 ], [ %161, %156 ]
  %164 = trunc i32 %163 to i16
  store i16 %164, ptr %133, align 2
  %165 = getelementptr inbounds i16, ptr %133, i64 1
  %166 = load ptr, ptr %29, align 8
  %167 = getelementptr inbounds %struct.t_meta, ptr %166, i32 0, i32 3
  %168 = load i16, ptr %167, align 2
  %169 = call i1 @llvm.is.constant.i16(i16 %168)
  br i1 %169, label %170, label %188

170:                                              ; preds = %162
  %171 = load ptr, ptr %29, align 8
  %172 = getelementptr inbounds %struct.t_meta, ptr %171, i32 0, i32 3
  %173 = load i16, ptr %172, align 2
  %174 = zext i16 %173 to i32
  %175 = shl i32 %174, 8
  %176 = ashr i32 %175, 8
  %177 = shl i32 %176, 8
  %178 = load ptr, ptr %29, align 8
  %179 = getelementptr inbounds %struct.t_meta, ptr %178, i32 0, i32 3
  %180 = load i16, ptr %179, align 2
  %181 = zext i16 %180 to i32
  %182 = shl i32 %181, 0
  %183 = ashr i32 %182, 8
  %184 = shl i32 %183, 0
  %185 = or i32 %177, %184
  %186 = trunc i32 %185 to i16
  %187 = zext i16 %186 to i32
  br label %194

188:                                              ; preds = %162
  %189 = load ptr, ptr %29, align 8
  %190 = getelementptr inbounds %struct.t_meta, ptr %189, i32 0, i32 3
  %191 = load i16, ptr %190, align 2
  %192 = call i16 @llvm.bswap.i16(i16 %191)
  %193 = zext i16 %192 to i32
  br label %194

194:                                              ; preds = %188, %170
  %195 = phi i32 [ %187, %170 ], [ %193, %188 ]
  %196 = trunc i32 %195 to i16
  store i16 %196, ptr %165, align 2
  store i32 0, ptr %33, align 4
  %197 = load ptr, ptr @bpf_map_lookup_elem, align 8
  %198 = call ptr %197(ptr noundef @countmin, ptr noundef %33)
  store ptr %198, ptr %34, align 8
  %199 = load ptr, ptr %34, align 8
  %200 = icmp ne ptr %199, null
  br i1 %200, label %202, label %201

201:                                              ; preds = %194
  store i32 4369, ptr %24, align 4
  br label %452

202:                                              ; preds = %194
  store i32 0, ptr %35, align 4
  br label %203

203:                                              ; preds = %448, %202
  %204 = load i32, ptr %35, align 4
  %205 = icmp slt i32 %204, 4
  br i1 %205, label %206, label %451

206:                                              ; preds = %203
  %207 = load ptr, ptr %27, align 8
  %208 = load i16, ptr %31, align 2
  %209 = zext i16 %208 to i32
  %210 = and i32 %209, 8191
  %211 = sext i32 %210 to i64
  %212 = getelementptr inbounds i8, ptr %207, i64 %211
  %213 = load ptr, ptr %26, align 8
  store ptr %212, ptr %11, align 8
  store ptr %213, ptr %12, align 8
  store ptr %36, ptr %13, align 8
  %214 = load ptr, ptr %11, align 8
  store ptr %214, ptr %14, align 8
  %215 = load ptr, ptr %14, align 8
  %216 = getelementptr inbounds %struct.ethhdr, ptr %215, i64 1
  %217 = load ptr, ptr %12, align 8
  %218 = icmp uge ptr %216, %217
  br i1 %218, label %219, label %223

219:                                              ; preds = %206
  %220 = load ptr, ptr @bpf_trace_printk, align 8
  %221 = call i64 (ptr, i32, ...) %220(ptr noundef @handle_pkt.____fmt, i32 noundef 21) #3
  store i64 %221, ptr %15, align 8
  %222 = load i64, ptr %15, align 8
  store i32 4369, ptr %10, align 4
  br label %313

223:                                              ; preds = %206
  %224 = load ptr, ptr %14, align 8
  %225 = getelementptr inbounds %struct.ethhdr, ptr %224, i32 0, i32 2
  %226 = load i16, ptr %225, align 1
  store i16 %226, ptr %16, align 2
  %227 = load i16, ptr %16, align 2
  %228 = zext i16 %227 to i32
  %229 = icmp eq i32 %228, 8
  br i1 %229, label %230, label %237

230:                                              ; preds = %223
  %231 = load ptr, ptr %11, align 8
  %232 = getelementptr inbounds i8, ptr %231, i64 14
  store ptr %232, ptr %19, align 8
  %233 = load ptr, ptr %19, align 8
  %234 = getelementptr inbounds %struct.iphdr, ptr %233, i64 1
  %235 = load ptr, ptr %12, align 8
  %236 = icmp uge ptr %234, %235
  br i1 %236, label %246, label %247

237:                                              ; preds = %223
  %238 = load ptr, ptr @bpf_trace_printk, align 8
  %239 = call i64 (ptr, i32, ...) %238(ptr noundef @handle_pkt.____fmt.4, i32 noundef 5) #3
  store i64 %239, ptr %17, align 8
  %240 = load i64, ptr %17, align 8
  %241 = load ptr, ptr @bpf_trace_printk, align 8
  %242 = load i16, ptr %16, align 2
  %243 = zext i16 %242 to i32
  %244 = call i64 (ptr, i32, ...) %241(ptr noundef @handle_pkt.____fmt.5, i32 noundef 13, i32 noundef %243) #3
  store i64 %244, ptr %18, align 8
  %245 = load i64, ptr %18, align 8
  store i32 4369, ptr %10, align 4
  br label %313

246:                                              ; preds = %230
  store i32 4369, ptr %10, align 4
  br label %313

247:                                              ; preds = %230
  %248 = load ptr, ptr %19, align 8
  %249 = getelementptr inbounds %struct.iphdr, ptr %248, i32 0, i32 8
  %250 = load i32, ptr %249, align 4
  %251 = load ptr, ptr %13, align 8
  store i32 %250, ptr %251, align 1
  %252 = load ptr, ptr %19, align 8
  %253 = getelementptr inbounds %struct.iphdr, ptr %252, i32 0, i32 8
  %254 = getelementptr inbounds %struct.anon.0, ptr %253, i32 0, i32 1
  %255 = load i32, ptr %254, align 4
  %256 = load ptr, ptr %13, align 8
  %257 = getelementptr inbounds %struct.pkt_5tuple, ptr %256, i32 0, i32 1
  store i32 %255, ptr %257, align 1
  %258 = load ptr, ptr %19, align 8
  %259 = getelementptr inbounds %struct.iphdr, ptr %258, i32 0, i32 6
  %260 = load i8, ptr %259, align 1
  %261 = load ptr, ptr %13, align 8
  %262 = getelementptr inbounds %struct.pkt_5tuple, ptr %261, i32 0, i32 4
  store i8 %260, ptr %262, align 1
  %263 = load ptr, ptr %19, align 8
  %264 = getelementptr inbounds %struct.iphdr, ptr %263, i32 0, i32 6
  %265 = load i8, ptr %264, align 1
  %266 = zext i8 %265 to i32
  switch i32 %266, label %308 [
    i32 6, label %267
    i32 17, label %286
  ]

267:                                              ; preds = %247
  %268 = load ptr, ptr %11, align 8
  %269 = getelementptr inbounds i8, ptr %268, i64 14
  %270 = getelementptr inbounds i8, ptr %269, i64 20
  store ptr %270, ptr %20, align 8
  %271 = load ptr, ptr %20, align 8
  %272 = getelementptr inbounds %struct.tcphdr, ptr %271, i64 1
  %273 = load ptr, ptr %12, align 8
  %274 = icmp ugt ptr %272, %273
  br i1 %274, label %275, label %276

275:                                              ; preds = %267
  store i32 4369, ptr %10, align 4
  br label %313

276:                                              ; preds = %267
  %277 = load ptr, ptr %20, align 8
  %278 = load i16, ptr %277, align 4
  %279 = load ptr, ptr %13, align 8
  %280 = getelementptr inbounds %struct.pkt_5tuple, ptr %279, i32 0, i32 2
  store i16 %278, ptr %280, align 1
  %281 = load ptr, ptr %20, align 8
  %282 = getelementptr inbounds %struct.tcphdr, ptr %281, i32 0, i32 1
  %283 = load i16, ptr %282, align 2
  %284 = load ptr, ptr %13, align 8
  %285 = getelementptr inbounds %struct.pkt_5tuple, ptr %284, i32 0, i32 3
  store i16 %283, ptr %285, align 1
  br label %312

286:                                              ; preds = %247
  %287 = load ptr, ptr %11, align 8
  %288 = getelementptr inbounds i8, ptr %287, i64 14
  %289 = getelementptr inbounds i8, ptr %288, i64 20
  store ptr %289, ptr %21, align 8
  %290 = load ptr, ptr %21, align 8
  %291 = getelementptr inbounds %struct.udphdr, ptr %290, i64 1
  %292 = load ptr, ptr %12, align 8
  %293 = icmp ugt ptr %291, %292
  br i1 %293, label %294, label %298

294:                                              ; preds = %286
  %295 = load ptr, ptr @bpf_trace_printk, align 8
  %296 = call i64 (ptr, i32, ...) %295(ptr noundef @handle_pkt.____fmt.6, i32 noundef 5) #3
  store i64 %296, ptr %22, align 8
  %297 = load i64, ptr %22, align 8
  store i32 4369, ptr %10, align 4
  br label %313

298:                                              ; preds = %286
  %299 = load ptr, ptr %21, align 8
  %300 = load i16, ptr %299, align 2
  %301 = load ptr, ptr %13, align 8
  %302 = getelementptr inbounds %struct.pkt_5tuple, ptr %301, i32 0, i32 2
  store i16 %300, ptr %302, align 1
  %303 = load ptr, ptr %21, align 8
  %304 = getelementptr inbounds %struct.udphdr, ptr %303, i32 0, i32 1
  %305 = load i16, ptr %304, align 2
  %306 = load ptr, ptr %13, align 8
  %307 = getelementptr inbounds %struct.pkt_5tuple, ptr %306, i32 0, i32 3
  store i16 %305, ptr %307, align 1
  br label %312

308:                                              ; preds = %247
  %309 = load ptr, ptr @bpf_trace_printk, align 8
  %310 = call i64 (ptr, i32, ...) %309(ptr noundef @handle_pkt.____fmt.7, i32 noundef 7) #3
  store i64 %310, ptr %23, align 8
  %311 = load i64, ptr %23, align 8
  store i32 4369, ptr %10, align 4
  br label %313

312:                                              ; preds = %298, %276
  store i32 0, ptr %10, align 4
  br label %313

313:                                              ; preds = %219, %237, %246, %275, %294, %308, %312
  %314 = load i32, ptr %10, align 4
  store i32 %314, ptr %38, align 4
  %315 = load i32, ptr %38, align 4
  %316 = icmp ne i32 %315, 0
  br i1 %316, label %317, label %387

317:                                              ; preds = %313
  %318 = load ptr, ptr @bpf_trace_printk, align 8
  %319 = load ptr, ptr %29, align 8
  %320 = getelementptr inbounds %struct.t_meta, ptr %319, i32 0, i32 0
  %321 = load i16, ptr %320, align 2
  %322 = call i1 @llvm.is.constant.i16(i16 %321)
  br i1 %322, label %323, label %341

323:                                              ; preds = %317
  %324 = load ptr, ptr %29, align 8
  %325 = getelementptr inbounds %struct.t_meta, ptr %324, i32 0, i32 0
  %326 = load i16, ptr %325, align 2
  %327 = zext i16 %326 to i32
  %328 = shl i32 %327, 8
  %329 = ashr i32 %328, 8
  %330 = shl i32 %329, 8
  %331 = load ptr, ptr %29, align 8
  %332 = getelementptr inbounds %struct.t_meta, ptr %331, i32 0, i32 0
  %333 = load i16, ptr %332, align 2
  %334 = zext i16 %333 to i32
  %335 = shl i32 %334, 0
  %336 = ashr i32 %335, 8
  %337 = shl i32 %336, 0
  %338 = or i32 %330, %337
  %339 = trunc i32 %338 to i16
  %340 = zext i16 %339 to i32
  br label %347

341:                                              ; preds = %317
  %342 = load ptr, ptr %29, align 8
  %343 = getelementptr inbounds %struct.t_meta, ptr %342, i32 0, i32 0
  %344 = load i16, ptr %343, align 2
  %345 = call i16 @llvm.bswap.i16(i16 %344)
  %346 = zext i16 %345 to i32
  br label %347

347:                                              ; preds = %341, %323
  %348 = phi i32 [ %340, %323 ], [ %346, %341 ]
  %349 = call i64 (ptr, i32, ...) %318(ptr noundef @ubcms.____fmt.1, i32 noundef 11, i32 noundef %348)
  store i64 %349, ptr %39, align 8
  %350 = load i64, ptr %39, align 8
  %351 = getelementptr inbounds [4 x i16], ptr %32, i64 0, i64 0
  %352 = load i16, ptr %351, align 2
  %353 = zext i16 %352 to i64
  %354 = getelementptr inbounds [4 x i64], ptr %40, i64 0, i64 0
  store i64 %353, ptr %354, align 8
  %355 = getelementptr inbounds [4 x i16], ptr %32, i64 0, i64 1
  %356 = load i16, ptr %355, align 2
  %357 = zext i16 %356 to i64
  %358 = getelementptr inbounds [4 x i64], ptr %40, i64 0, i64 1
  store i64 %357, ptr %358, align 8
  %359 = getelementptr inbounds [4 x i16], ptr %32, i64 0, i64 2
  %360 = load i16, ptr %359, align 2
  %361 = zext i16 %360 to i64
  %362 = getelementptr inbounds [4 x i64], ptr %40, i64 0, i64 2
  store i64 %361, ptr %362, align 8
  %363 = getelementptr inbounds [4 x i16], ptr %32, i64 0, i64 3
  %364 = load i16, ptr %363, align 2
  %365 = zext i16 %364 to i64
  %366 = getelementptr inbounds [4 x i64], ptr %40, i64 0, i64 3
  store i64 %365, ptr %366, align 8
  %367 = load ptr, ptr @bpf_trace_vprintk, align 8
  %368 = getelementptr inbounds [4 x i64], ptr %40, i64 0, i64 0
  %369 = call i64 %367(ptr noundef @ubcms.___fmt, i32 noundef 19, ptr noundef %368, i32 noundef 32)
  store i64 %369, ptr %41, align 8
  %370 = load i64, ptr %41, align 8
  %371 = load ptr, ptr @bpf_trace_printk, align 8
  %372 = load i32, ptr %35, align 4
  %373 = call i64 (ptr, i32, ...) %371(ptr noundef @ubcms.____fmt.2, i32 noundef 27, i32 noundef %372)
  store i64 %373, ptr %42, align 8
  %374 = load i64, ptr %42, align 8
  %375 = load ptr, ptr @bpf_trace_printk, align 8
  %376 = load i32, ptr %35, align 4
  %377 = load i32, ptr %35, align 4
  %378 = sext i32 %377 to i64
  %379 = getelementptr inbounds [4 x i16], ptr %32, i64 0, i64 %378
  %380 = load i16, ptr %379, align 2
  %381 = zext i16 %380 to i32
  %382 = load i16, ptr %31, align 2
  %383 = zext i16 %382 to i32
  %384 = call i64 (ptr, i32, ...) %375(ptr noundef @ubcms.____fmt.3, i32 noundef 29, i32 noundef %376, i32 noundef %381, i32 noundef %383)
  store i64 %384, ptr %43, align 8
  %385 = load i64, ptr %43, align 8
  %386 = load i32, ptr %38, align 4
  store i32 %386, ptr %24, align 4
  br label %452

387:                                              ; preds = %313
  %388 = getelementptr inbounds [4 x i16], ptr %37, i64 0, i64 0
  store ptr %36, ptr %6, align 8
  store i64 13, ptr %7, align 8
  store ptr %388, ptr %8, align 8
  %389 = load ptr, ptr %6, align 8
  %390 = load i64, ptr %7, align 8
  %391 = call i64 @xxhash64(ptr noundef %389, i64 noundef %390, i64 noundef 77)
  store i64 %391, ptr %9, align 8
  %392 = load i64, ptr %9, align 8
  %393 = and i64 %392, 65535
  %394 = trunc i64 %393 to i16
  %395 = load ptr, ptr %8, align 8
  store i16 %394, ptr %395, align 2
  %396 = load i64, ptr %9, align 8
  %397 = lshr i64 %396, 16
  %398 = and i64 %397, 65535
  %399 = trunc i64 %398 to i16
  %400 = load ptr, ptr %8, align 8
  %401 = getelementptr inbounds i16, ptr %400, i64 1
  store i16 %399, ptr %401, align 2
  %402 = load i64, ptr %9, align 8
  %403 = lshr i64 %402, 32
  %404 = and i64 %403, 65535
  %405 = trunc i64 %404 to i16
  %406 = load ptr, ptr %8, align 8
  %407 = getelementptr inbounds i16, ptr %406, i64 2
  store i16 %405, ptr %407, align 2
  %408 = load i64, ptr %9, align 8
  %409 = lshr i64 %408, 48
  %410 = trunc i64 %409 to i16
  %411 = load ptr, ptr %8, align 8
  %412 = getelementptr inbounds i16, ptr %411, i64 3
  store i16 %410, ptr %412, align 2
  %413 = load ptr, ptr %34, align 8
  %414 = getelementptr inbounds [4 x i16], ptr %37, i64 0, i64 0
  store ptr %413, ptr %2, align 8
  store ptr %414, ptr %3, align 8
  store i32 0, ptr %4, align 4
  br label %415

415:                                              ; preds = %419, %387
  %416 = load i32, ptr %4, align 4
  %417 = sext i32 %416 to i64
  %418 = icmp ult i64 %417, 4
  br i1 %418, label %419, label %438

419:                                              ; preds = %415
  %420 = load ptr, ptr %3, align 8
  %421 = load i32, ptr %4, align 4
  %422 = sext i32 %421 to i64
  %423 = getelementptr inbounds i16, ptr %420, i64 %422
  %424 = load i16, ptr %423, align 2
  %425 = zext i16 %424 to i32
  %426 = and i32 %425, 1048575
  store i32 %426, ptr %5, align 4
  %427 = load ptr, ptr %2, align 8
  %428 = load i32, ptr %4, align 4
  %429 = sext i32 %428 to i64
  %430 = getelementptr inbounds [4 x [1048576 x i64]], ptr %427, i64 0, i64 %429
  %431 = load i32, ptr %5, align 4
  %432 = zext i32 %431 to i64
  %433 = getelementptr inbounds [1048576 x i64], ptr %430, i64 0, i64 %432
  %434 = load i64, ptr %433, align 8
  %435 = add i64 %434, 1
  store i64 %435, ptr %433, align 8
  %436 = load i32, ptr %4, align 4
  %437 = add nsw i32 %436, 1
  store i32 %437, ptr %4, align 4
  br label %415, !llvm.loop !3

438:                                              ; preds = %415
  %439 = load i32, ptr %35, align 4
  %440 = sext i32 %439 to i64
  %441 = getelementptr inbounds [4 x i16], ptr %32, i64 0, i64 %440
  %442 = load i16, ptr %441, align 2
  %443 = zext i16 %442 to i32
  %444 = load i16, ptr %31, align 2
  %445 = zext i16 %444 to i32
  %446 = add nsw i32 %445, %443
  %447 = trunc i32 %446 to i16
  store i16 %447, ptr %31, align 2
  br label %448

448:                                              ; preds = %438
  %449 = load i32, ptr %35, align 4
  %450 = add nsw i32 %449, 1
  store i32 %450, ptr %35, align 4
  br label %203, !llvm.loop !5

451:                                              ; preds = %203
  store i32 4369, ptr %24, align 4
  br label %452

452:                                              ; preds = %451, %347, %201, %64
  %453 = load i32, ptr %24, align 4
  ret i32 %453
}

; Function Attrs: convergent nocallback nofree nosync nounwind willreturn memory(none)
declare i1 @llvm.is.constant.i16(i16) #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare i16 @llvm.bswap.i16(i16) #2

; Function Attrs: noinline nounwind optnone
define internal i64 @xxhash64(ptr noundef %0, i64 noundef %1, i64 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca i64, align 8
  %6 = alloca i64, align 8
  store ptr %0, ptr %4, align 8
  store i64 %1, ptr %5, align 8
  store i64 %2, ptr %6, align 8
  %7 = load i64, ptr %5, align 8
  %8 = icmp uge i64 %7, 32
  br i1 %8, label %9, label %14

9:                                                ; preds = %3
  %10 = load ptr, ptr %4, align 8
  %11 = load i64, ptr %5, align 8
  %12 = load i64, ptr %6, align 8
  %13 = call i64 @h32bytes_3(ptr noundef %10, i64 noundef %11, i64 noundef %12)
  br label %17

14:                                               ; preds = %3
  %15 = load i64, ptr %6, align 8
  %16 = add i64 %15, 2870177450012600261
  br label %17

17:                                               ; preds = %14, %9
  %18 = phi i64 [ %13, %9 ], [ %16, %14 ]
  %19 = load i64, ptr %5, align 8
  %20 = add i64 %18, %19
  %21 = load ptr, ptr %4, align 8
  %22 = load i64, ptr %5, align 8
  %23 = and i64 %22, -32
  %24 = getelementptr inbounds i8, ptr %21, i64 %23
  %25 = load i64, ptr %5, align 8
  %26 = and i64 %25, 31
  %27 = call i64 @finalize(i64 noundef %20, ptr noundef %24, i64 noundef %26)
  ret i64 %27
}

; Function Attrs: noinline nounwind optnone
define internal i64 @finalize(i64 noundef %0, ptr noundef %1, i64 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca i64, align 8
  %7 = alloca i32, align 4
  %8 = alloca i64, align 8
  %9 = alloca i64, align 8
  %10 = alloca i64, align 8
  %11 = alloca i64, align 8
  %12 = alloca i32, align 4
  %13 = alloca i64, align 8
  %14 = alloca i64, align 8
  %15 = alloca i32, align 4
  %16 = alloca i64, align 8
  %17 = alloca i64, align 8
  %18 = alloca i32, align 4
  %19 = alloca ptr, align 8
  %20 = alloca ptr, align 8
  %21 = alloca ptr, align 8
  %22 = alloca i64, align 8
  %23 = alloca i64, align 8
  %24 = alloca i32, align 4
  %25 = alloca i64, align 8
  %26 = alloca i32, align 4
  %27 = alloca i64, align 8
  %28 = alloca i32, align 4
  %29 = alloca i64, align 8
  %30 = alloca ptr, align 8
  %31 = alloca i64, align 8
  store i64 %0, ptr %29, align 8
  store ptr %1, ptr %30, align 8
  store i64 %2, ptr %31, align 8
  %32 = load i64, ptr %31, align 8
  %33 = icmp uge i64 %32, 8
  br i1 %33, label %34, label %117

34:                                               ; preds = %3
  %35 = load i64, ptr %29, align 8
  %36 = load ptr, ptr %30, align 8
  store ptr %36, ptr %21, align 8
  store i64 0, ptr %22, align 8
  %37 = load ptr, ptr %21, align 8
  store ptr %37, ptr %5, align 8
  %38 = load ptr, ptr %5, align 8
  %39 = load i8, ptr %38, align 1
  %40 = zext i8 %39 to i64
  %41 = load ptr, ptr %5, align 8
  %42 = getelementptr inbounds i8, ptr %41, i64 1
  %43 = load i8, ptr %42, align 1
  %44 = zext i8 %43 to i64
  %45 = shl i64 %44, 8
  %46 = or i64 %40, %45
  %47 = load ptr, ptr %5, align 8
  %48 = getelementptr inbounds i8, ptr %47, i64 2
  %49 = load i8, ptr %48, align 1
  %50 = zext i8 %49 to i64
  %51 = shl i64 %50, 16
  %52 = or i64 %46, %51
  %53 = load ptr, ptr %5, align 8
  %54 = getelementptr inbounds i8, ptr %53, i64 3
  %55 = load i8, ptr %54, align 1
  %56 = zext i8 %55 to i64
  %57 = shl i64 %56, 24
  %58 = or i64 %52, %57
  %59 = load ptr, ptr %5, align 8
  %60 = getelementptr inbounds i8, ptr %59, i64 4
  %61 = load i8, ptr %60, align 1
  %62 = zext i8 %61 to i64
  %63 = shl i64 %62, 32
  %64 = or i64 %58, %63
  %65 = load ptr, ptr %5, align 8
  %66 = getelementptr inbounds i8, ptr %65, i64 5
  %67 = load i8, ptr %66, align 1
  %68 = zext i8 %67 to i64
  %69 = shl i64 %68, 40
  %70 = or i64 %64, %69
  %71 = load ptr, ptr %5, align 8
  %72 = getelementptr inbounds i8, ptr %71, i64 6
  %73 = load i8, ptr %72, align 1
  %74 = zext i8 %73 to i64
  %75 = shl i64 %74, 48
  %76 = or i64 %70, %75
  %77 = load ptr, ptr %5, align 8
  %78 = getelementptr inbounds i8, ptr %77, i64 7
  %79 = load i8, ptr %78, align 1
  %80 = zext i8 %79 to i64
  %81 = shl i64 %80, 56
  %82 = or i64 %76, %81
  %83 = load i64, ptr %22, align 8
  store i64 %82, ptr %8, align 8
  store i64 %83, ptr %9, align 8
  %84 = load i64, ptr %9, align 8
  %85 = load i64, ptr %8, align 8
  %86 = mul i64 %85, -4417276706812531889
  %87 = add i64 %84, %86
  store i64 %87, ptr %6, align 8
  store i32 31, ptr %7, align 4
  %88 = load i64, ptr %6, align 8
  %89 = load i32, ptr %7, align 4
  %90 = zext i32 %89 to i64
  %91 = shl i64 %88, %90
  %92 = load i64, ptr %6, align 8
  %93 = load i32, ptr %7, align 4
  %94 = sub nsw i32 64, %93
  %95 = zext i32 %94 to i64
  %96 = lshr i64 %92, %95
  %97 = or i64 %91, %96
  %98 = mul i64 %97, -7046029288634856825
  %99 = xor i64 %35, %98
  store i64 %99, ptr %23, align 8
  store i32 27, ptr %24, align 4
  %100 = load i64, ptr %23, align 8
  %101 = load i32, ptr %24, align 4
  %102 = zext i32 %101 to i64
  %103 = shl i64 %100, %102
  %104 = load i64, ptr %23, align 8
  %105 = load i32, ptr %24, align 4
  %106 = sub nsw i32 64, %105
  %107 = zext i32 %106 to i64
  %108 = lshr i64 %104, %107
  %109 = or i64 %103, %108
  %110 = mul i64 %109, -7046029288634856825
  %111 = add i64 %110, -8796714831421723037
  %112 = load ptr, ptr %30, align 8
  %113 = getelementptr inbounds i8, ptr %112, i64 8
  %114 = load i64, ptr %31, align 8
  %115 = sub i64 %114, 8
  %116 = call i64 @finalize(i64 noundef %111, ptr noundef %113, i64 noundef %115)
  br label %222

117:                                              ; preds = %3
  %118 = load i64, ptr %31, align 8
  %119 = icmp uge i64 %118, 4
  br i1 %119, label %120, label %165

120:                                              ; preds = %117
  %121 = load i64, ptr %29, align 8
  %122 = load ptr, ptr %30, align 8
  store ptr %122, ptr %20, align 8
  %123 = load ptr, ptr %20, align 8
  store ptr %123, ptr %4, align 8
  %124 = load ptr, ptr %4, align 8
  %125 = load i8, ptr %124, align 1
  %126 = zext i8 %125 to i32
  %127 = load ptr, ptr %4, align 8
  %128 = getelementptr inbounds i8, ptr %127, i64 1
  %129 = load i8, ptr %128, align 1
  %130 = zext i8 %129 to i32
  %131 = shl i32 %130, 8
  %132 = or i32 %126, %131
  %133 = load ptr, ptr %4, align 8
  %134 = getelementptr inbounds i8, ptr %133, i64 2
  %135 = load i8, ptr %134, align 1
  %136 = zext i8 %135 to i32
  %137 = shl i32 %136, 16
  %138 = or i32 %132, %137
  %139 = load ptr, ptr %4, align 8
  %140 = getelementptr inbounds i8, ptr %139, i64 3
  %141 = load i8, ptr %140, align 1
  %142 = zext i8 %141 to i32
  %143 = shl i32 %142, 24
  %144 = or i32 %138, %143
  %145 = zext i32 %144 to i64
  %146 = mul i64 %145, -7046029288634856825
  %147 = xor i64 %121, %146
  store i64 %147, ptr %25, align 8
  store i32 23, ptr %26, align 4
  %148 = load i64, ptr %25, align 8
  %149 = load i32, ptr %26, align 4
  %150 = zext i32 %149 to i64
  %151 = shl i64 %148, %150
  %152 = load i64, ptr %25, align 8
  %153 = load i32, ptr %26, align 4
  %154 = sub nsw i32 64, %153
  %155 = zext i32 %154 to i64
  %156 = lshr i64 %152, %155
  %157 = or i64 %151, %156
  %158 = mul i64 %157, -4417276706812531889
  %159 = add i64 %158, 1609587929392839161
  %160 = load ptr, ptr %30, align 8
  %161 = getelementptr inbounds i8, ptr %160, i64 4
  %162 = load i64, ptr %31, align 8
  %163 = sub i64 %162, 4
  %164 = call i64 @finalize(i64 noundef %159, ptr noundef %161, i64 noundef %163)
  br label %220

165:                                              ; preds = %117
  %166 = load i64, ptr %31, align 8
  %167 = icmp ugt i64 %166, 0
  br i1 %167, label %168, label %192

168:                                              ; preds = %165
  %169 = load i64, ptr %29, align 8
  %170 = load ptr, ptr %30, align 8
  store ptr %170, ptr %19, align 8
  %171 = load ptr, ptr %19, align 8
  %172 = load i8, ptr %171, align 1
  %173 = zext i8 %172 to i64
  %174 = mul i64 %173, 2870177450012600261
  %175 = xor i64 %169, %174
  store i64 %175, ptr %27, align 8
  store i32 11, ptr %28, align 4
  %176 = load i64, ptr %27, align 8
  %177 = load i32, ptr %28, align 4
  %178 = zext i32 %177 to i64
  %179 = shl i64 %176, %178
  %180 = load i64, ptr %27, align 8
  %181 = load i32, ptr %28, align 4
  %182 = sub nsw i32 64, %181
  %183 = zext i32 %182 to i64
  %184 = lshr i64 %180, %183
  %185 = or i64 %179, %184
  %186 = mul i64 %185, -7046029288634856825
  %187 = load ptr, ptr %30, align 8
  %188 = getelementptr inbounds i8, ptr %187, i64 1
  %189 = load i64, ptr %31, align 8
  %190 = sub i64 %189, 1
  %191 = call i64 @finalize(i64 noundef %186, ptr noundef %188, i64 noundef %190)
  br label %218

192:                                              ; preds = %165
  %193 = load i64, ptr %29, align 8
  store i64 %193, ptr %10, align 8
  store i64 -4417276706812531889, ptr %11, align 8
  store i32 33, ptr %12, align 4
  %194 = load i64, ptr %10, align 8
  %195 = load i64, ptr %10, align 8
  %196 = load i32, ptr %12, align 4
  %197 = zext i32 %196 to i64
  %198 = lshr i64 %195, %197
  %199 = xor i64 %194, %198
  %200 = load i64, ptr %11, align 8
  %201 = mul i64 %199, %200
  store i64 %201, ptr %13, align 8
  store i64 1609587929392839161, ptr %14, align 8
  store i32 29, ptr %15, align 4
  %202 = load i64, ptr %13, align 8
  %203 = load i64, ptr %13, align 8
  %204 = load i32, ptr %15, align 4
  %205 = zext i32 %204 to i64
  %206 = lshr i64 %203, %205
  %207 = xor i64 %202, %206
  %208 = load i64, ptr %14, align 8
  %209 = mul i64 %207, %208
  store i64 %209, ptr %16, align 8
  store i64 1, ptr %17, align 8
  store i32 32, ptr %18, align 4
  %210 = load i64, ptr %16, align 8
  %211 = load i64, ptr %16, align 8
  %212 = load i32, ptr %18, align 4
  %213 = zext i32 %212 to i64
  %214 = lshr i64 %211, %213
  %215 = xor i64 %210, %214
  %216 = load i64, ptr %17, align 8
  %217 = mul i64 %215, %216
  br label %218

218:                                              ; preds = %192, %168
  %219 = phi i64 [ %191, %168 ], [ %217, %192 ]
  br label %220

220:                                              ; preds = %218, %120
  %221 = phi i64 [ %164, %120 ], [ %219, %218 ]
  br label %222

222:                                              ; preds = %220, %34
  %223 = phi i64 [ %116, %34 ], [ %221, %220 ]
  ret i64 %223
}

; Function Attrs: noinline nounwind optnone
define internal i64 @h32bytes_3(ptr noundef %0, i64 noundef %1, i64 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca i64, align 8
  %6 = alloca i64, align 8
  store ptr %0, ptr %4, align 8
  store i64 %1, ptr %5, align 8
  store i64 %2, ptr %6, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = load i64, ptr %5, align 8
  %9 = load i64, ptr %6, align 8
  %10 = add i64 %9, -7046029288634856825
  %11 = add i64 %10, -4417276706812531889
  %12 = load i64, ptr %6, align 8
  %13 = add i64 %12, -4417276706812531889
  %14 = load i64, ptr %6, align 8
  %15 = load i64, ptr %6, align 8
  %16 = sub i64 %15, -7046029288634856825
  %17 = call i64 @h32bytes_4(ptr noundef %7, i64 noundef %8, i64 noundef %11, i64 noundef %13, i64 noundef %14, i64 noundef %16)
  ret i64 %17
}

; Function Attrs: noinline nounwind optnone
define internal i64 @h32bytes_4(ptr noundef %0, i64 noundef %1, i64 noundef %2, i64 noundef %3, i64 noundef %4, i64 noundef %5) #0 {
  %7 = alloca i64, align 8
  %8 = alloca i32, align 4
  %9 = alloca i64, align 8
  %10 = alloca i64, align 8
  %11 = alloca i64, align 8
  %12 = alloca i64, align 8
  %13 = alloca i64, align 8
  %14 = alloca i32, align 4
  %15 = alloca i64, align 8
  %16 = alloca i64, align 8
  %17 = alloca i64, align 8
  %18 = alloca i64, align 8
  %19 = alloca i64, align 8
  %20 = alloca i32, align 4
  %21 = alloca i64, align 8
  %22 = alloca i64, align 8
  %23 = alloca i64, align 8
  %24 = alloca i64, align 8
  %25 = alloca i64, align 8
  %26 = alloca i32, align 4
  %27 = alloca i64, align 8
  %28 = alloca i64, align 8
  %29 = alloca i64, align 8
  %30 = alloca i64, align 8
  %31 = alloca ptr, align 8
  %32 = alloca ptr, align 8
  %33 = alloca ptr, align 8
  %34 = alloca ptr, align 8
  %35 = alloca i64, align 8
  %36 = alloca i32, align 4
  %37 = alloca i64, align 8
  %38 = alloca i64, align 8
  %39 = alloca i64, align 8
  %40 = alloca i32, align 4
  %41 = alloca i64, align 8
  %42 = alloca i64, align 8
  %43 = alloca i64, align 8
  %44 = alloca i32, align 4
  %45 = alloca i64, align 8
  %46 = alloca i64, align 8
  %47 = alloca i64, align 8
  %48 = alloca i32, align 4
  %49 = alloca i64, align 8
  %50 = alloca i64, align 8
  %51 = alloca ptr, align 8
  %52 = alloca i64, align 8
  %53 = alloca ptr, align 8
  %54 = alloca i64, align 8
  %55 = alloca ptr, align 8
  %56 = alloca i64, align 8
  %57 = alloca ptr, align 8
  %58 = alloca i64, align 8
  %59 = alloca i64, align 8
  %60 = alloca i32, align 4
  %61 = alloca i64, align 8
  %62 = alloca i32, align 4
  %63 = alloca i64, align 8
  %64 = alloca i32, align 4
  %65 = alloca i64, align 8
  %66 = alloca i32, align 4
  %67 = alloca ptr, align 8
  %68 = alloca i64, align 8
  %69 = alloca i64, align 8
  %70 = alloca i64, align 8
  %71 = alloca i64, align 8
  %72 = alloca i64, align 8
  store ptr %0, ptr %67, align 8
  store i64 %1, ptr %68, align 8
  store i64 %2, ptr %69, align 8
  store i64 %3, ptr %70, align 8
  store i64 %4, ptr %71, align 8
  store i64 %5, ptr %72, align 8
  %73 = load i64, ptr %68, align 8
  %74 = icmp uge i64 %73, 32
  br i1 %74, label %75, label %340

75:                                               ; preds = %6
  %76 = load ptr, ptr %67, align 8
  %77 = getelementptr inbounds i8, ptr %76, i64 32
  %78 = load i64, ptr %68, align 8
  %79 = sub i64 %78, 32
  %80 = load ptr, ptr %67, align 8
  %81 = load i64, ptr %69, align 8
  store ptr %80, ptr %51, align 8
  store i64 %81, ptr %52, align 8
  %82 = load ptr, ptr %51, align 8
  store ptr %82, ptr %34, align 8
  %83 = load ptr, ptr %34, align 8
  %84 = load i8, ptr %83, align 1
  %85 = zext i8 %84 to i64
  %86 = load ptr, ptr %34, align 8
  %87 = getelementptr inbounds i8, ptr %86, i64 1
  %88 = load i8, ptr %87, align 1
  %89 = zext i8 %88 to i64
  %90 = shl i64 %89, 8
  %91 = or i64 %85, %90
  %92 = load ptr, ptr %34, align 8
  %93 = getelementptr inbounds i8, ptr %92, i64 2
  %94 = load i8, ptr %93, align 1
  %95 = zext i8 %94 to i64
  %96 = shl i64 %95, 16
  %97 = or i64 %91, %96
  %98 = load ptr, ptr %34, align 8
  %99 = getelementptr inbounds i8, ptr %98, i64 3
  %100 = load i8, ptr %99, align 1
  %101 = zext i8 %100 to i64
  %102 = shl i64 %101, 24
  %103 = or i64 %97, %102
  %104 = load ptr, ptr %34, align 8
  %105 = getelementptr inbounds i8, ptr %104, i64 4
  %106 = load i8, ptr %105, align 1
  %107 = zext i8 %106 to i64
  %108 = shl i64 %107, 32
  %109 = or i64 %103, %108
  %110 = load ptr, ptr %34, align 8
  %111 = getelementptr inbounds i8, ptr %110, i64 5
  %112 = load i8, ptr %111, align 1
  %113 = zext i8 %112 to i64
  %114 = shl i64 %113, 40
  %115 = or i64 %109, %114
  %116 = load ptr, ptr %34, align 8
  %117 = getelementptr inbounds i8, ptr %116, i64 6
  %118 = load i8, ptr %117, align 1
  %119 = zext i8 %118 to i64
  %120 = shl i64 %119, 48
  %121 = or i64 %115, %120
  %122 = load ptr, ptr %34, align 8
  %123 = getelementptr inbounds i8, ptr %122, i64 7
  %124 = load i8, ptr %123, align 1
  %125 = zext i8 %124 to i64
  %126 = shl i64 %125, 56
  %127 = or i64 %121, %126
  %128 = load i64, ptr %52, align 8
  store i64 %127, ptr %49, align 8
  store i64 %128, ptr %50, align 8
  %129 = load i64, ptr %50, align 8
  %130 = load i64, ptr %49, align 8
  %131 = mul i64 %130, -4417276706812531889
  %132 = add i64 %129, %131
  store i64 %132, ptr %47, align 8
  store i32 31, ptr %48, align 4
  %133 = load i64, ptr %47, align 8
  %134 = load i32, ptr %48, align 4
  %135 = zext i32 %134 to i64
  %136 = shl i64 %133, %135
  %137 = load i64, ptr %47, align 8
  %138 = load i32, ptr %48, align 4
  %139 = sub nsw i32 64, %138
  %140 = zext i32 %139 to i64
  %141 = lshr i64 %137, %140
  %142 = or i64 %136, %141
  %143 = mul i64 %142, -7046029288634856825
  %144 = load ptr, ptr %67, align 8
  %145 = getelementptr inbounds i8, ptr %144, i64 8
  %146 = load i64, ptr %70, align 8
  store ptr %145, ptr %53, align 8
  store i64 %146, ptr %54, align 8
  %147 = load ptr, ptr %53, align 8
  store ptr %147, ptr %33, align 8
  %148 = load ptr, ptr %33, align 8
  %149 = load i8, ptr %148, align 1
  %150 = zext i8 %149 to i64
  %151 = load ptr, ptr %33, align 8
  %152 = getelementptr inbounds i8, ptr %151, i64 1
  %153 = load i8, ptr %152, align 1
  %154 = zext i8 %153 to i64
  %155 = shl i64 %154, 8
  %156 = or i64 %150, %155
  %157 = load ptr, ptr %33, align 8
  %158 = getelementptr inbounds i8, ptr %157, i64 2
  %159 = load i8, ptr %158, align 1
  %160 = zext i8 %159 to i64
  %161 = shl i64 %160, 16
  %162 = or i64 %156, %161
  %163 = load ptr, ptr %33, align 8
  %164 = getelementptr inbounds i8, ptr %163, i64 3
  %165 = load i8, ptr %164, align 1
  %166 = zext i8 %165 to i64
  %167 = shl i64 %166, 24
  %168 = or i64 %162, %167
  %169 = load ptr, ptr %33, align 8
  %170 = getelementptr inbounds i8, ptr %169, i64 4
  %171 = load i8, ptr %170, align 1
  %172 = zext i8 %171 to i64
  %173 = shl i64 %172, 32
  %174 = or i64 %168, %173
  %175 = load ptr, ptr %33, align 8
  %176 = getelementptr inbounds i8, ptr %175, i64 5
  %177 = load i8, ptr %176, align 1
  %178 = zext i8 %177 to i64
  %179 = shl i64 %178, 40
  %180 = or i64 %174, %179
  %181 = load ptr, ptr %33, align 8
  %182 = getelementptr inbounds i8, ptr %181, i64 6
  %183 = load i8, ptr %182, align 1
  %184 = zext i8 %183 to i64
  %185 = shl i64 %184, 48
  %186 = or i64 %180, %185
  %187 = load ptr, ptr %33, align 8
  %188 = getelementptr inbounds i8, ptr %187, i64 7
  %189 = load i8, ptr %188, align 1
  %190 = zext i8 %189 to i64
  %191 = shl i64 %190, 56
  %192 = or i64 %186, %191
  %193 = load i64, ptr %54, align 8
  store i64 %192, ptr %45, align 8
  store i64 %193, ptr %46, align 8
  %194 = load i64, ptr %46, align 8
  %195 = load i64, ptr %45, align 8
  %196 = mul i64 %195, -4417276706812531889
  %197 = add i64 %194, %196
  store i64 %197, ptr %43, align 8
  store i32 31, ptr %44, align 4
  %198 = load i64, ptr %43, align 8
  %199 = load i32, ptr %44, align 4
  %200 = zext i32 %199 to i64
  %201 = shl i64 %198, %200
  %202 = load i64, ptr %43, align 8
  %203 = load i32, ptr %44, align 4
  %204 = sub nsw i32 64, %203
  %205 = zext i32 %204 to i64
  %206 = lshr i64 %202, %205
  %207 = or i64 %201, %206
  %208 = mul i64 %207, -7046029288634856825
  %209 = load ptr, ptr %67, align 8
  %210 = getelementptr inbounds i8, ptr %209, i64 16
  %211 = load i64, ptr %71, align 8
  store ptr %210, ptr %55, align 8
  store i64 %211, ptr %56, align 8
  %212 = load ptr, ptr %55, align 8
  store ptr %212, ptr %32, align 8
  %213 = load ptr, ptr %32, align 8
  %214 = load i8, ptr %213, align 1
  %215 = zext i8 %214 to i64
  %216 = load ptr, ptr %32, align 8
  %217 = getelementptr inbounds i8, ptr %216, i64 1
  %218 = load i8, ptr %217, align 1
  %219 = zext i8 %218 to i64
  %220 = shl i64 %219, 8
  %221 = or i64 %215, %220
  %222 = load ptr, ptr %32, align 8
  %223 = getelementptr inbounds i8, ptr %222, i64 2
  %224 = load i8, ptr %223, align 1
  %225 = zext i8 %224 to i64
  %226 = shl i64 %225, 16
  %227 = or i64 %221, %226
  %228 = load ptr, ptr %32, align 8
  %229 = getelementptr inbounds i8, ptr %228, i64 3
  %230 = load i8, ptr %229, align 1
  %231 = zext i8 %230 to i64
  %232 = shl i64 %231, 24
  %233 = or i64 %227, %232
  %234 = load ptr, ptr %32, align 8
  %235 = getelementptr inbounds i8, ptr %234, i64 4
  %236 = load i8, ptr %235, align 1
  %237 = zext i8 %236 to i64
  %238 = shl i64 %237, 32
  %239 = or i64 %233, %238
  %240 = load ptr, ptr %32, align 8
  %241 = getelementptr inbounds i8, ptr %240, i64 5
  %242 = load i8, ptr %241, align 1
  %243 = zext i8 %242 to i64
  %244 = shl i64 %243, 40
  %245 = or i64 %239, %244
  %246 = load ptr, ptr %32, align 8
  %247 = getelementptr inbounds i8, ptr %246, i64 6
  %248 = load i8, ptr %247, align 1
  %249 = zext i8 %248 to i64
  %250 = shl i64 %249, 48
  %251 = or i64 %245, %250
  %252 = load ptr, ptr %32, align 8
  %253 = getelementptr inbounds i8, ptr %252, i64 7
  %254 = load i8, ptr %253, align 1
  %255 = zext i8 %254 to i64
  %256 = shl i64 %255, 56
  %257 = or i64 %251, %256
  %258 = load i64, ptr %56, align 8
  store i64 %257, ptr %41, align 8
  store i64 %258, ptr %42, align 8
  %259 = load i64, ptr %42, align 8
  %260 = load i64, ptr %41, align 8
  %261 = mul i64 %260, -4417276706812531889
  %262 = add i64 %259, %261
  store i64 %262, ptr %39, align 8
  store i32 31, ptr %40, align 4
  %263 = load i64, ptr %39, align 8
  %264 = load i32, ptr %40, align 4
  %265 = zext i32 %264 to i64
  %266 = shl i64 %263, %265
  %267 = load i64, ptr %39, align 8
  %268 = load i32, ptr %40, align 4
  %269 = sub nsw i32 64, %268
  %270 = zext i32 %269 to i64
  %271 = lshr i64 %267, %270
  %272 = or i64 %266, %271
  %273 = mul i64 %272, -7046029288634856825
  %274 = load ptr, ptr %67, align 8
  %275 = getelementptr inbounds i8, ptr %274, i64 24
  %276 = load i64, ptr %72, align 8
  store ptr %275, ptr %57, align 8
  store i64 %276, ptr %58, align 8
  %277 = load ptr, ptr %57, align 8
  store ptr %277, ptr %31, align 8
  %278 = load ptr, ptr %31, align 8
  %279 = load i8, ptr %278, align 1
  %280 = zext i8 %279 to i64
  %281 = load ptr, ptr %31, align 8
  %282 = getelementptr inbounds i8, ptr %281, i64 1
  %283 = load i8, ptr %282, align 1
  %284 = zext i8 %283 to i64
  %285 = shl i64 %284, 8
  %286 = or i64 %280, %285
  %287 = load ptr, ptr %31, align 8
  %288 = getelementptr inbounds i8, ptr %287, i64 2
  %289 = load i8, ptr %288, align 1
  %290 = zext i8 %289 to i64
  %291 = shl i64 %290, 16
  %292 = or i64 %286, %291
  %293 = load ptr, ptr %31, align 8
  %294 = getelementptr inbounds i8, ptr %293, i64 3
  %295 = load i8, ptr %294, align 1
  %296 = zext i8 %295 to i64
  %297 = shl i64 %296, 24
  %298 = or i64 %292, %297
  %299 = load ptr, ptr %31, align 8
  %300 = getelementptr inbounds i8, ptr %299, i64 4
  %301 = load i8, ptr %300, align 1
  %302 = zext i8 %301 to i64
  %303 = shl i64 %302, 32
  %304 = or i64 %298, %303
  %305 = load ptr, ptr %31, align 8
  %306 = getelementptr inbounds i8, ptr %305, i64 5
  %307 = load i8, ptr %306, align 1
  %308 = zext i8 %307 to i64
  %309 = shl i64 %308, 40
  %310 = or i64 %304, %309
  %311 = load ptr, ptr %31, align 8
  %312 = getelementptr inbounds i8, ptr %311, i64 6
  %313 = load i8, ptr %312, align 1
  %314 = zext i8 %313 to i64
  %315 = shl i64 %314, 48
  %316 = or i64 %310, %315
  %317 = load ptr, ptr %31, align 8
  %318 = getelementptr inbounds i8, ptr %317, i64 7
  %319 = load i8, ptr %318, align 1
  %320 = zext i8 %319 to i64
  %321 = shl i64 %320, 56
  %322 = or i64 %316, %321
  %323 = load i64, ptr %58, align 8
  store i64 %322, ptr %37, align 8
  store i64 %323, ptr %38, align 8
  %324 = load i64, ptr %38, align 8
  %325 = load i64, ptr %37, align 8
  %326 = mul i64 %325, -4417276706812531889
  %327 = add i64 %324, %326
  store i64 %327, ptr %35, align 8
  store i32 31, ptr %36, align 4
  %328 = load i64, ptr %35, align 8
  %329 = load i32, ptr %36, align 4
  %330 = zext i32 %329 to i64
  %331 = shl i64 %328, %330
  %332 = load i64, ptr %35, align 8
  %333 = load i32, ptr %36, align 4
  %334 = sub nsw i32 64, %333
  %335 = zext i32 %334 to i64
  %336 = lshr i64 %332, %335
  %337 = or i64 %331, %336
  %338 = mul i64 %337, -7046029288634856825
  %339 = call i64 @h32bytes_4(ptr noundef %77, i64 noundef %79, i64 noundef %143, i64 noundef %208, i64 noundef %273, i64 noundef %338)
  br label %472

340:                                              ; preds = %6
  %341 = load i64, ptr %69, align 8
  store i64 %341, ptr %59, align 8
  store i32 1, ptr %60, align 4
  %342 = load i64, ptr %59, align 8
  %343 = load i32, ptr %60, align 4
  %344 = zext i32 %343 to i64
  %345 = shl i64 %342, %344
  %346 = load i64, ptr %59, align 8
  %347 = load i32, ptr %60, align 4
  %348 = sub nsw i32 64, %347
  %349 = zext i32 %348 to i64
  %350 = lshr i64 %346, %349
  %351 = or i64 %345, %350
  %352 = load i64, ptr %70, align 8
  store i64 %352, ptr %61, align 8
  store i32 7, ptr %62, align 4
  %353 = load i64, ptr %61, align 8
  %354 = load i32, ptr %62, align 4
  %355 = zext i32 %354 to i64
  %356 = shl i64 %353, %355
  %357 = load i64, ptr %61, align 8
  %358 = load i32, ptr %62, align 4
  %359 = sub nsw i32 64, %358
  %360 = zext i32 %359 to i64
  %361 = lshr i64 %357, %360
  %362 = or i64 %356, %361
  %363 = add i64 %351, %362
  %364 = load i64, ptr %71, align 8
  store i64 %364, ptr %63, align 8
  store i32 12, ptr %64, align 4
  %365 = load i64, ptr %63, align 8
  %366 = load i32, ptr %64, align 4
  %367 = zext i32 %366 to i64
  %368 = shl i64 %365, %367
  %369 = load i64, ptr %63, align 8
  %370 = load i32, ptr %64, align 4
  %371 = sub nsw i32 64, %370
  %372 = zext i32 %371 to i64
  %373 = lshr i64 %369, %372
  %374 = or i64 %368, %373
  %375 = add i64 %363, %374
  %376 = load i64, ptr %72, align 8
  store i64 %376, ptr %65, align 8
  store i32 18, ptr %66, align 4
  %377 = load i64, ptr %65, align 8
  %378 = load i32, ptr %66, align 4
  %379 = zext i32 %378 to i64
  %380 = shl i64 %377, %379
  %381 = load i64, ptr %65, align 8
  %382 = load i32, ptr %66, align 4
  %383 = sub nsw i32 64, %382
  %384 = zext i32 %383 to i64
  %385 = lshr i64 %381, %384
  %386 = or i64 %380, %385
  %387 = add i64 %375, %386
  %388 = load i64, ptr %69, align 8
  store i64 %387, ptr %11, align 8
  store i64 %388, ptr %12, align 8
  %389 = load i64, ptr %11, align 8
  %390 = load i64, ptr %12, align 8
  store i64 %390, ptr %9, align 8
  store i64 0, ptr %10, align 8
  %391 = load i64, ptr %10, align 8
  %392 = load i64, ptr %9, align 8
  %393 = mul i64 %392, -4417276706812531889
  %394 = add i64 %391, %393
  store i64 %394, ptr %7, align 8
  store i32 31, ptr %8, align 4
  %395 = load i64, ptr %7, align 8
  %396 = load i32, ptr %8, align 4
  %397 = zext i32 %396 to i64
  %398 = shl i64 %395, %397
  %399 = load i64, ptr %7, align 8
  %400 = load i32, ptr %8, align 4
  %401 = sub nsw i32 64, %400
  %402 = zext i32 %401 to i64
  %403 = lshr i64 %399, %402
  %404 = or i64 %398, %403
  %405 = mul i64 %404, -7046029288634856825
  %406 = xor i64 %389, %405
  %407 = mul i64 %406, -7046029288634856825
  %408 = add i64 %407, -8796714831421723037
  %409 = load i64, ptr %70, align 8
  store i64 %408, ptr %17, align 8
  store i64 %409, ptr %18, align 8
  %410 = load i64, ptr %17, align 8
  %411 = load i64, ptr %18, align 8
  store i64 %411, ptr %15, align 8
  store i64 0, ptr %16, align 8
  %412 = load i64, ptr %16, align 8
  %413 = load i64, ptr %15, align 8
  %414 = mul i64 %413, -4417276706812531889
  %415 = add i64 %412, %414
  store i64 %415, ptr %13, align 8
  store i32 31, ptr %14, align 4
  %416 = load i64, ptr %13, align 8
  %417 = load i32, ptr %14, align 4
  %418 = zext i32 %417 to i64
  %419 = shl i64 %416, %418
  %420 = load i64, ptr %13, align 8
  %421 = load i32, ptr %14, align 4
  %422 = sub nsw i32 64, %421
  %423 = zext i32 %422 to i64
  %424 = lshr i64 %420, %423
  %425 = or i64 %419, %424
  %426 = mul i64 %425, -7046029288634856825
  %427 = xor i64 %410, %426
  %428 = mul i64 %427, -7046029288634856825
  %429 = add i64 %428, -8796714831421723037
  %430 = load i64, ptr %71, align 8
  store i64 %429, ptr %23, align 8
  store i64 %430, ptr %24, align 8
  %431 = load i64, ptr %23, align 8
  %432 = load i64, ptr %24, align 8
  store i64 %432, ptr %21, align 8
  store i64 0, ptr %22, align 8
  %433 = load i64, ptr %22, align 8
  %434 = load i64, ptr %21, align 8
  %435 = mul i64 %434, -4417276706812531889
  %436 = add i64 %433, %435
  store i64 %436, ptr %19, align 8
  store i32 31, ptr %20, align 4
  %437 = load i64, ptr %19, align 8
  %438 = load i32, ptr %20, align 4
  %439 = zext i32 %438 to i64
  %440 = shl i64 %437, %439
  %441 = load i64, ptr %19, align 8
  %442 = load i32, ptr %20, align 4
  %443 = sub nsw i32 64, %442
  %444 = zext i32 %443 to i64
  %445 = lshr i64 %441, %444
  %446 = or i64 %440, %445
  %447 = mul i64 %446, -7046029288634856825
  %448 = xor i64 %431, %447
  %449 = mul i64 %448, -7046029288634856825
  %450 = add i64 %449, -8796714831421723037
  %451 = load i64, ptr %72, align 8
  store i64 %450, ptr %29, align 8
  store i64 %451, ptr %30, align 8
  %452 = load i64, ptr %29, align 8
  %453 = load i64, ptr %30, align 8
  store i64 %453, ptr %27, align 8
  store i64 0, ptr %28, align 8
  %454 = load i64, ptr %28, align 8
  %455 = load i64, ptr %27, align 8
  %456 = mul i64 %455, -4417276706812531889
  %457 = add i64 %454, %456
  store i64 %457, ptr %25, align 8
  store i32 31, ptr %26, align 4
  %458 = load i64, ptr %25, align 8
  %459 = load i32, ptr %26, align 4
  %460 = zext i32 %459 to i64
  %461 = shl i64 %458, %460
  %462 = load i64, ptr %25, align 8
  %463 = load i32, ptr %26, align 4
  %464 = sub nsw i32 64, %463
  %465 = zext i32 %464 to i64
  %466 = lshr i64 %462, %465
  %467 = or i64 %461, %466
  %468 = mul i64 %467, -7046029288634856825
  %469 = xor i64 %452, %468
  %470 = mul i64 %469, -7046029288634856825
  %471 = add i64 %470, -8796714831421723037
  br label %472

472:                                              ; preds = %340, %75
  %473 = phi i64 [ %339, %75 ], [ %471, %340 ]
  ret i64 %473
}

attributes #0 = { noinline nounwind optnone "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { convergent nocallback nofree nosync nounwind willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #3 = { nounwind }

!llvm.module.flags = !{!0, !1}
!llvm.ident = !{!2}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"frame-pointer", i32 2}
!2 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!3 = distinct !{!3, !4}
!4 = !{!"llvm.loop.mustprogress"}
!5 = distinct !{!5, !4}
