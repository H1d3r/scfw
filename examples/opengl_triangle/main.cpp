//
//=============================================================================
// OpenGL Triangle
//=============================================================================
//
// A minimal OpenGL triangle rendered from shellcode. This example doubles
// as a guide for understanding scfw's compile-time options and the
// trade-offs between shellcode size and compatibility.
//
// This example dynamically loads user32.dll, gdi32.dll, and opengl32.dll,
// creates a window, sets up an OpenGL context, and renders a colored
// triangle in a message loop.
//
//=============================================================================
// CONFIGURATION
//=============================================================================
//
// Try enabling/disabling these to see how they affect shellcode size:
//
//   USE_GETPROCADDRESS - Use GetProcAddress for symbol lookup instead of
//                        our manual PE export table walker.
//
//   USE_DEFWINDOWPROCA - Import DefWindowProcA from user32.dll directly.
//                        If disabled, we import NtdllDefWindowProc_A from
//                        ntdll.dll instead (see the forwarded export
//                        discussion below).
//
//   USE_FORWARDER      - Enable forwarded export handling in our custom
//                        PE export table walker.
//
// Recommended combinations (from smallest to safest):
//
//   - USE_DEFWINDOWPROCA only:
//     Smallest shellcode. Uses our manual PE walker (no GetProcAddress)
//     and imports DefWindowProcA directly from user32.dll. The catch is
//     that DefWindowProcA is a forwarded export, and our manual walker
//     can't handle those by default. This works IF the OS resolves it
//     for us in the export table (which it usually does), but it's not
//     guaranteed.
//
//   - All USE_* disabled (default):
//     Good middle ground. Uses our manual PE walker without forwarder
//     support, but sidesteps the problem entirely by importing
//     NtdllDefWindowProc_A directly from ntdll.dll. Slightly bigger
//     than USE_DEFWINDOWPROCA alone (extra module import), but doesn't
//     rely on undocumented behavior. Fewer GetProcAddress calls means
//     smaller shellcode than the "safe" option below.
//
//   - USE_GETPROCADDRESS + USE_DEFWINDOWPROCA:
//     Safest option. GetProcAddress handles forwarded exports natively,
//     so importing DefWindowProcA just works. Maximum compatibility at
//     the cost of a bigger shellcode (GetProcAddress resolution code +
//     full module search).
//
//   - USE_DEFWINDOWPROCA + USE_FORWARDER:
//     Alternative safe option. Uses our custom PE walker with built-in
//     forwarder handling instead of GetProcAddress. Correctly resolves
//     DefWindowProcA -> NtdllDefWindowProc_A at runtime. Produces the
//     biggest shellcode because the forwarder code is included.
//
// In general, SCFW_ENABLE_FIND_MODULE_FORWARDER makes sense when:
//   - You have a very large shellcode with many imports, where avoiding
//     GetProcAddress calls saves more bytes than the forwarder code adds.
//   - You want to avoid using GetProcAddress for some reason (stealth,
//     hook avoidance, etc.).
//

//#define USE_GETPROCADDRESS
//#define USE_DEFWINDOWPROCA
//#define USE_FORWARDER

//=============================================================================
// SCFW COMPILE-TIME OPTIONS
//=============================================================================

//
// These must be defined BEFORE including runtime.h.
//

//
// SCFW_ENABLE_FULL_MODULE_SEARCH
//
// By default, scfw has a fast-path for ntdll.dll and kernel32.dll that
// reads them directly from known PEB offsets (2nd and 3rd entries in
// InLoadOrderModuleList) instead of walking the entire list. When we
// import many modules dynamically anyway, the fast-path code is dead
// weight - the generic PEB walker handles everything. Defining this
// disables the fast-path, making the shellcode smaller.
//
// We only need this when USE_GETPROCADDRESS is enabled, because that
// path uses SCFW_FLAG_DYNAMIC_RESOLVE which requires resolving
// GetProcAddress from kernel32.dll - and the fast-path is needed for
// that initial bootstrap.
//

//
// SCFW_ENABLE_LOAD_MODULE
//
// Resolves LoadLibraryA at init time. Required for SCFW_FLAG_DYNAMIC_LOAD,
// which we use to load user32.dll, gdi32.dll, and opengl32.dll - DLLs
// that aren't loaded in the target process by default.
//

//
// SCFW_ENABLE_UNLOAD_MODULE
//
// Resolves FreeLibrary at init time. Required for SCFW_FLAG_DYNAMIC_UNLOAD.
// If we don't care about cleaning up loaded DLLs after ourselves, we can
// leave this disabled to save a few bytes (no FreeLibrary calls emitted).
//

//
// SCFW_ENABLE_LOOKUP_SYMBOL
//
// Resolves GetProcAddress at init time. Required for SCFW_FLAG_DYNAMIC_RESOLVE.
// This is the interesting one - we only need it because DefWindowProcA
// _might be_ a "forwarded export" in user32.dll (forwarding to
// ntdll.dll!NtdllDefWindowProc_A). Our custom PE export table walker
// can't handle forwarded exports by default, so we fall back to
// GetProcAddress which handles them natively.
//
// We have two alternatives to avoid needing GetProcAddress:
//
//   - Define SCFW_ENABLE_FIND_MODULE_FORWARDER to teach our custom walker
//     how to follow forwarded exports.
//
//     Downside: more code in the shellcode binary.
//
//   - Import NtdllDefWindowProc_A directly from ntdll.dll instead of
//     DefWindowProcA from user32.dll, sidestepping the forwarded export
//     entirely.
//
//     Downside: relies on undocumented ntdll internals, and the extra
//               module import may increase shellcode size.
//
//     (Also note: the ntdll.dll module must use FLAGS(0) to override
//     SCFW_MODULE_DEFAULT_FLAGS, since we don't want DYNAMIC_LOAD for
//     ntdll - it's always loaded.)
//

#define SCFW_ENABLE_LOAD_MODULE
// #define SCFW_ENABLE_UNLOAD_MODULE
#define SCFW_ENABLE_LOOKUP_SYMBOL

#ifdef USE_GETPROCADDRESS
#   define SCFW_ENABLE_FULL_MODULE_SEARCH
#   define SCFW_MODULE_DEFAULT_FLAGS   (SCFW_FLAG_DYNAMIC_LOAD | SCFW_FLAG_DYNAMIC_RESOLVE)
#else
    // No SCFW_FLAG_DYNAMIC_RESOLVE in the default flags means we use our
    // manual PE export table walker for symbol lookup instead of GetProcAddress.
#   define SCFW_MODULE_DEFAULT_FLAGS   (SCFW_FLAG_DYNAMIC_LOAD)
#endif

#ifdef USE_FORWARDER
#   define SCFW_ENABLE_FIND_MODULE_FORWARDER
#endif

#include <scfw/runtime.h>
#include <scfw/platform/windows/usermode.h>

#include <gl/gl.h>

//
// Required for floating-point operations. The MSVC CRT normally provides
// this symbol; since we're freestanding, we define it ourselves.
//
// Note on float constants:
//   - On x86 (-mno-sse), the compiler moves float literals directly into
//     FPU registers via integer instructions (no .rdata needed).
//   - On x64, float constants are stored in .rdata (which gets merged
//     into .text) and accessed via RIP-relative addressing.
//
extern "C" __attribute__((used)) int _fltused = 0;

#ifndef USE_DEFWINDOWPROCA
//
// Forward declaration of NtdllDefWindowProc_A from ntdll.dll.
// This is the actual implementation that user32!DefWindowProcA
// forwards to. We import it directly when USE_DEFWINDOWPROCA is
// not defined, avoiding the forwarded export issue.
//
extern "C"
LRESULT
WINAPI
NtdllDefWindowProc_A(
    _In_ HWND hWnd,
    _In_ UINT Msg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);
#endif

//=============================================================================
// IMPORT TABLE
//=============================================================================

IMPORT_BEGIN();
    //
    // kernel32.dll is always loaded in every process, so we don't need
    // DYNAMIC_LOAD. FLAGS(0) overrides SCFW_MODULE_DEFAULT_FLAGS to skip
    // the LoadLibraryA call.
    //
    IMPORT_MODULE("kernel32.dll", FLAGS(0));
        IMPORT_SYMBOL(LoadLibraryA);
        IMPORT_SYMBOL(GetModuleHandleA);

    IMPORT_MODULE("user32.dll");
        IMPORT_SYMBOL(RegisterClassA);
        IMPORT_SYMBOL(CreateWindowExA);
#ifdef USE_DEFWINDOWPROCA
        IMPORT_SYMBOL(DefWindowProcA);
#endif
        IMPORT_SYMBOL(ShowWindow);
        IMPORT_SYMBOL(PeekMessageA);
        IMPORT_SYMBOL(TranslateMessage);
        IMPORT_SYMBOL(DispatchMessageA);
        IMPORT_SYMBOL(GetDC);
        IMPORT_SYMBOL(PostQuitMessage);

    IMPORT_MODULE("gdi32.dll");
        IMPORT_SYMBOL(ChoosePixelFormat);
        IMPORT_SYMBOL(SetPixelFormat);
        IMPORT_SYMBOL(SwapBuffers);

    IMPORT_MODULE("opengl32.dll");
        IMPORT_SYMBOL(wglCreateContext);
        IMPORT_SYMBOL(wglMakeCurrent);
        IMPORT_SYMBOL(wglDeleteContext);

        IMPORT_SYMBOL(glClearColor);
        IMPORT_SYMBOL(glClear);
        IMPORT_SYMBOL(glBegin);
        IMPORT_SYMBOL(glEnd);
        IMPORT_SYMBOL(glVertex2f);
        IMPORT_SYMBOL(glColor3f);
        IMPORT_SYMBOL(glViewport);
        IMPORT_SYMBOL(glMatrixMode);
        IMPORT_SYMBOL(glLoadIdentity);

#ifndef USE_DEFWINDOWPROCA
    //
    // Import the ntdll version of DefWindowProcA directly, avoiding the
    // forwarded export in user32.dll. FLAGS(0) is required here - without
    // it, SCFW_MODULE_DEFAULT_FLAGS would apply DYNAMIC_LOAD, which would
    // try to LoadLibraryA("ntdll.dll") (unnecessary, it's always loaded).
    //
    IMPORT_MODULE("ntdll.dll", FLAGS(0));
        IMPORT_SYMBOL(NtdllDefWindowProc_A);
#endif
IMPORT_END();

#ifndef USE_DEFWINDOWPROCA
    // Alias so the rest of the code can use DefWindowProcA regardless of
    // which import path was chosen.
#   define DefWindowProcA NtdllDefWindowProc_A
#endif

//
// Global variables. GLOBAL() handles PIC on x86 - these are stored
// in .text and accessed through position-independent wrappers.
//
GLOBAL(HGLRC, g_hglrc);
GLOBAL(HDC,   g_hdc);
GLOBAL(bool,  g_running, true);

namespace sc {

//=============================================================================
// Window Procedure
//=============================================================================

static LRESULT __stdcall WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            g_running = false;
            return 0;

        case WM_SIZE:
            glViewport(0, 0, LOWORD(lParam), HIWORD(lParam));
            return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

//=============================================================================
// Rendering
//=============================================================================

void RenderTriangle()
{
    glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);

    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();

    glBegin(GL_TRIANGLES);
        glColor3f(1.0f, 0.0f, 0.0f); glVertex2f( 0.0f,  0.5f);  // Red top
        glColor3f(0.0f, 1.0f, 0.0f); glVertex2f(-0.5f, -0.5f);  // Green bottom-left
        glColor3f(0.0f, 0.0f, 1.0f); glVertex2f( 0.5f, -0.5f);  // Blue bottom-right
    glEnd();

    SwapBuffers(g_hdc);
}

//=============================================================================
// Entry Point
//=============================================================================

extern "C" void __fastcall entry(void* argument1, void* argument2)
{
    (void)argument1;
    (void)argument2;

    //
    // Register window class.
    //
    // Note the _(&WndProc) wrapper: on x86, function pointers are
    // compile-time absolute addresses that are wrong when the shellcode
    // is loaded at a different base. _() applies the PIC delta to get
    // the correct runtime address. On x64 this is a no-op (RIP-relative
    // addressing handles it).
    //
    WNDCLASSA wc{};
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.lpfnWndProc = _(&WndProc);
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = _("OpenGLTriangle");

    if (!RegisterClassA(&wc)) return;

    // Create window
    HWND hwnd = CreateWindowExA(
        0,
        _("OpenGLTriangle"),
        _("OpenGL Triangle"),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        NULL, NULL,
        wc.hInstance,
        NULL
    );

    if (!hwnd) return;

    // Get device context
    g_hdc = GetDC(hwnd);
    if (!g_hdc) return;

    // Set pixel format
    PIXELFORMATDESCRIPTOR pfd{};
    pfd.nSize = sizeof(PIXELFORMATDESCRIPTOR);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32;
    pfd.cDepthBits = 24;
    pfd.iLayerType = PFD_MAIN_PLANE;

    int pixelFormat = ChoosePixelFormat(g_hdc, &pfd);
    if (!pixelFormat) return;

    if (!SetPixelFormat(g_hdc, pixelFormat, &pfd)) return;

    // Create OpenGL context
    g_hglrc = wglCreateContext(g_hdc);
    if (!g_hglrc) return;

    if (!wglMakeCurrent(g_hdc, g_hglrc)) {
        wglDeleteContext(g_hglrc);
        return;
    }

    // Set initial viewport
    glViewport(0, 0, 800, 600);

    // Show window
    ShowWindow(hwnd, SW_SHOW);

    // Message loop
    MSG msg{};
    while (g_running) {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                g_running = false;
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        if (g_running) {
            RenderTriangle();
        }
    }

    // Cleanup
    wglMakeCurrent(NULL, NULL);
    wglDeleteContext(g_hglrc);
}

} // namespace sc
