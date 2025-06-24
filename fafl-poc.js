const shm_id = 0x39;const sem_shm_id=0x8;const crash_shm_id=0x9;
function open_shm(id, size) {
    const shmat_addr = Module.getExportByName(null, "shmat");
    //console.log("[-] shmat address: "+shmat_addr);
    const shmat = new NativeFunction(shmat_addr, 'pointer', ['int', 'pointer', 'int']);
    return shmat(parseInt(id), ptr(0), 0);
}

const sem_post_addr = Module.getExportByName(null, "sem_post");
const sem_post = new NativeFunction(sem_post_addr, "int", ["pointer"]);

let pc = undefined;

if (Process.arch == "x64") {
  pc = "rip";
} else {
  console.log("[!] Unknown architecture!", Process.arch);
}

var stalker_instrumentation = new CModule(`
#include <gum/gumstalker.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void afl_map_fill (GumCpuContext * cpu_context, gpointer user_data);

struct _user_data {
    uint8_t *afl_area_ptr;
    uintptr_t module_start;
    uintptr_t module_end;
    uintptr_t base;
    uintptr_t prev_loc;
    uint8_t coverage;
  };


bool is_within_module(uintptr_t pc, uintptr_t s, uintptr_t e) {
  return (pc <= e) && (pc >= s);
}


static void afl_map_fill(GumCpuContext * cpu_context, gpointer user_data) {
    struct _user_data *ud = (struct _user_data*)user_data;
    uintptr_t cur_loc = cpu_context->${pc} - ud->base;
    uint8_t * afl_area_ptr = ud->afl_area_ptr;

    cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= 65536 - 1;
    afl_area_ptr[cur_loc ^ ud->prev_loc]++;
    ud->prev_loc = cur_loc >> 1;
}



void transform(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data) {
    cs_insn *insn;
    struct _user_data *ud = (struct _user_data *)user_data;
    gpointer block_start = NULL;

    while (gum_stalker_iterator_next(iterator, &insn)) {
        if (is_within_module((uintptr_t)insn->address, ud->module_start, ud->module_end) && (ud->coverage == 1)) {
            // Check if this is the first instruction in the block
            if (block_start == NULL) {
                block_start = (gpointer)insn->address;
                gum_stalker_iterator_put_callout(iterator, afl_map_fill, user_data, NULL);
            }
        }
        gum_stalker_iterator_keep(iterator);
    }
}


`);

//printf("+---------------- BASIC BLOCK 0x%lx \n", insn->address);
//printf("| 0x%lx: %s %s\n", insn->address, insn->mnemonic, insn->op_str);

var moduleName = Process.mainModule.name;
var target_fun_addr;
var base;
var range_base;
var range_base_end;
//const _user_data = Memory.alloc(40);
const _user_data = Memory.alloc(41);

console.log("Module Name: "+moduleName);
console.log("Enumerating symbols...");
Module.enumerateSymbols(moduleName, {
    onMatch: function(symbol) {
        console.log("---> Symbol: " + symbol.name + " - Address: " + symbol.address);
        //if(symbol.name === "vuln"){
        //if(symbol.name === "http_request_parse"){ // CVE-2015-3294
        //if(symbol.name === "tcp_request"){ // CVE-2015-3294
        //if(symbol.name === "dlt_daemon_process_client_connect"){ 
       // if(symbol.name === "do_tcp_connection"){
	    //if(symbol.name === "dhcp_packet"){ //dnsmasqdhcp
	    if(symbol.name === "udhcp_recv_kernel_packet"){ 
	   // if(symbol.name === "udhcp_add_binary_option"){ 
        //if(symbol.name === "recv_dhcp_packet"){
	    //if(symbol.name === "receive_query"){
        console.log("FOUND! Symbol: " + symbol.name + " - Address: " + symbol.address);
        target_fun_addr=symbol.address;
        }
    },
    onComplete: function() {
        console.log("Finished enumerating symbols.");
    }
});

base = target_fun_addr;

// RANGES
console.log("Enumerating ranges...");
Process.enumerateRanges('r-x').forEach(function(range) {
    if(range.file){console.log("Range: "+range.file.path);}
    if(range.file && range.file.path === Process.mainModule.path){
        console.log("[JS] Range base: "+range.base);
        console.log("[JS] Range size: "+range.size);
        range_base=range.base;
        range_base_end=range.base.add(range.size);
        console.log("[JS ]Range base end: "+range_base_end);
    }
});

var afl_area_ptr = open_shm(shm_id, 65536)

_user_data.writePointer(afl_area_ptr);
_user_data.add(8).writePointer(range_base);
_user_data.add(16).writePointer(range_base_end);
_user_data.add(24).writePointer(base);
//_user_data.add(32).writeInt(0);
_user_data.add(32).writeU64(0);
_user_data.add(40).writeU8(0);

var sem_shm = open_shm(sem_shm_id,256);
var crash_shm = open_shm(crash_shm_id,32);

console.log("HERE");
const stalkerOptions = {
        transform: stalker_instrumentation.transform,
        data: _user_data,
        events: {
            call: false,
            ret: false,
            exec: false,
            block: false,
            compile: false
        },
        recyclePool: true,
        trustThreshold: 0
    };

Process.setExceptionHandler(function (details) {
        Memory.writeU32(crash_shm, 0x0b);
        sem_post(sem_shm);
       //console.log("CRASH " +JSON.stringify(details.context, null, 2));
        //return false;
        //Process.exit();
        return false;
    });

var followedThreads = new Set();
//let hitCount = 0 ;

Interceptor.attach(target_fun_addr, {
	onEnter: function(args) {
		_user_data.add(32).writeU64(0);
		_user_data.add(40).writeU8(1);
   		// hitCount++;
		//console.log(`[*] Interceptor onEnter (${Date.now()}) - Thread: ${threadId}`);
		//Stalker.follow(Process.getCurrentThreadId(), stalkerOptions);
		var threadId = Process.getCurrentThreadId();
		if (!followedThreads.has(threadId)) {  
			Stalker.follow(Process.getCurrentThreadId(), stalkerOptions);
	   		followedThreads.add(threadId);
		}
	},
	onLeave: function(retval) {
	  //Stalker.unfollow(Process.getCurrentThreadId());
  //     Stalker.invalidate(Process.getCurrentThreadId(),target_fun_addr);
		_user_data.add(40).writeU8(0);
		Stalker.flush(); 
		Stalker.garbageCollect();
		sem_post(sem_shm);
	}
});

