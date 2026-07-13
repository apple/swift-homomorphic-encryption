// Copyright 2025-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation

/// Errors that can occur during memory mapping operations.
public enum MemoryMappingError: Error {
    /// The file being mapped is empty.
    case emptyFile
    /// A system error occurred with an associated error code and message.
    /// - Parameters:
    ///   - Int32: The system error code.
    ///   - String: A human-readable error message.
    case systemError(Int32, String)

    /// Captures the current system error state.
    ///
    /// This method reads the current value of `errno` and creates a `systemError`
    /// case with the error code and its corresponding error message.
    ///
    /// - Returns: A `MemoryMappingError.systemError` containing the error code and message.
    public static func catchSystemErrno() -> Self {
        let err = errno
        let message = String(cString: strerror(err))
        return .systemError(err, message)
    }
}

/// Utilities for memory-mapping files.
///
/// This type provides static methods for memory-mapping files into the process's address space,
/// allowing efficient access to file contents without loading the entire file into memory.
public enum MemoryMapping {
    /// Opens and memory-maps a file at the specified path.
    ///
    /// This method opens the file in read-only mode, retrieves its size, and creates a memory mapping
    /// using `mmap`. The file descriptor is automatically closed after the mapping is created.
    ///
    /// - Parameter path: The file system path to the file to be mapped.
    /// - Returns: An `UnsafeMutableRawBufferPointer` representing the mapped memory region.
    /// - Throws: `MemoryMappingError.emptyFile` if the file is empty,
    ///           `MemoryMappingError.systemError` if a system error occurs during opening,
    ///           stat retrieval, or mapping.
    public static func openFile(path: String) throws -> UnsafeMutableRawBufferPointer {
        let fd = open(path, O_RDONLY)
        guard fd != -1 else {
            throw MemoryMappingError.catchSystemErrno()
        }
        defer {
            close(fd)
        }

        var stat = stat()
        if fstat(fd, &stat) != 0 {
            throw MemoryMappingError.catchSystemErrno()
        }
        let fileSize = Int(stat.st_size)
        guard fileSize > 0 else {
            throw MemoryMappingError.emptyFile
        }
        guard let addr = mmap(nil, fileSize, PROT_READ, MAP_SHARED, fd, 0),
              addr != MAP_FAILED
        else {
            throw MemoryMappingError.catchSystemErrno()
        }
        return UnsafeMutableRawBufferPointer(start: addr, count: fileSize)
    }

    /// Unmaps a previously mapped memory region.
    ///
    /// This method releases the memory mapping created by `openFile(path:)` or `mmap`.
    /// After calling this method, the buffer should no longer be accessed.
    ///
    /// - Parameter buffer: The buffer representing the mapped memory region to unmap.
    public static func unmap(_ buffer: UnsafeMutableRawBufferPointer) {
        munmap(buffer.baseAddress, buffer.count)
    }

    /// Executes a closure with a memory-mapped file, automatically managing the mapping lifecycle.
    ///
    /// This convenience method opens and maps the file at the specified path, creates a `RawSpan`
    /// from the mapped memory, executes the provided closure with the span, and automatically
    /// unmaps the file when the closure completes (including if an error is thrown).
    ///
    /// - Parameters:
    ///   - path: The file system path to the file to be mapped.
    ///   - body: A closure that takes a `RawSpan` representing the file's contents and returns a value.
    /// - Returns: The value returned by the closure.
    /// - Throws: Errors from `openFile(path:)` or any error thrown by the closure.
    public static func withMemoryMappedFile<R>(path: String,
                                               _ body: (RawSpan) throws -> R) throws -> R
    {
        let buffer = try Self.openFile(path: path)
        defer {
            Self.unmap(buffer)
        }
        let span = RawSpan(_unsafeBytes: buffer)
        return try body(span)
    }
}
