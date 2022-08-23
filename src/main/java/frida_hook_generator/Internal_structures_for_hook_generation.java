/* 
 * BSD 2-Clause License
 *
 * Copyright (c) 2022, CENSUS
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package frida_hook_generator;

import java.util.ArrayList;
import java.util.HashMap;

import ghidra.program.model.address.Address;

public class Internal_structures_for_hook_generation {
	
	//This is a hashmap that contains for which addresses a hook has been generated, in the current batch. It is a data structure held so that interceptor hooks are not being created for the same address twice. The value of the field will be in the following format: <index in sequence of addresses>|<reason for hook 1>|<reason for hook 2>|....
	protected HashMap<String, String> Addresses_for_current_hook_str;
	protected int how_many_addresses_have_been_hooked_so_far_in_this_batch;
	//This ArrayList keeps the addresses for which a hook is generated, by order of appearance. The reason is that when reasons of hooking are also printed in the console, we might need fast lookup for the address that came at position X.
	protected ArrayList<Address> addresses_for_which_hook_is_generated_in_order_of_appearance;
	//This ArrayList keeps the hooks which are generated for every individual address, in order of appearance.
	protected ArrayList<String> hooks_generated_per_address_in_order_of_appearance;
	
	public Internal_structures_for_hook_generation() {
		this.Addresses_for_current_hook_str= new HashMap<String, String>();
		this.how_many_addresses_have_been_hooked_so_far_in_this_batch=0;
		this.addresses_for_which_hook_is_generated_in_order_of_appearance=new ArrayList<Address>();
		this.hooks_generated_per_address_in_order_of_appearance=new ArrayList<String>();
	}
}
