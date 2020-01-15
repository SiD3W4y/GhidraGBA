/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidragba;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class GhidraGBALoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "GBA ROM";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		// Too small to contain header
		if(provider.length() < 0xc0)
			return loadSpecs;
		
		// Invalid magic byte
		if(provider.readByte(0xb2) != (byte)0x96)
			return loadSpecs;
		
		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v4t", "default"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		Memory mem = program.getMemory();
		FlatProgramAPI api = new FlatProgramAPI(program);
				
		try {
			mem.createUninitializedBlock("WRAM", api.toAddr(0x2000000), 0x40000, false).setExecute(true);
			mem.createUninitializedBlock("IRAM", api.toAddr(0x3000000), 0x08000, false).setExecute(true);
			mem.createUninitializedBlock("IO", api.toAddr(0x4000000), 0x003ff, false).setWrite(true);
			mem.createUninitializedBlock("VRAM", api.toAddr(0x6000000), 0x18000, false).setExecute(true);
			mem.createUninitializedBlock("OBJ", api.toAddr(0x7000000), 0x400, false).setExecute(true);
			mem.createInitializedBlock("ROM", api.toAddr(0x8000000), provider.getInputStream(0), 0x1000000, monitor, false).setExecute(true);
			
			api.addEntryPoint(api.toAddr(0x8000000));
			api.createFunction(api.toAddr(0x8000000), "_entry");
		} catch (Exception e) {
			log.appendException(e);
		}
	}
}
