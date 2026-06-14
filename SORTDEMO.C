/* SORTDEMO -This program graphically demonstrates six common sorting
 * algorithms. It prints 25 or 43 horizontal bars of different lengths
 * in random order, then sorts the bars from shortest to longest.
 * The program can beep to generate different pitches, depending on the
 * length and position of the bar.
 *
 * The program can be created for DOS or OS/2. To create for OS/2, define
 * the symbol OS2. Command lines for DOS and OS/2 are shown below:
 *
 * DOS:
 *    cl /Lr sortdemo.c graphics.lib
 *
 * Source selftest harness:
 *    cl /Od /DSORTDEMO_FUNCTION_SELFTEST sortdemo.c
 * The selftest build exits with DOS errorlevel 255 when all checks pass.
 *
 * OS/2:
 *    cl /Lp /DOS2 sortdemo.c grtextp.lib
 */

#include <STRING.H>         // strlen
#include <STDIO.H>          // sprintf
#include <CONIO.H>          // getch
#include <STDLIB.H>         // srand, rand, toupper
#include <MALLOC.H>         // malloc, free
#include <TIME.H>           // time, clock

#ifdef SORTDEMO_FUNCTION_SELFTEST
static int sortdemo_textrows_calls;
static int sortdemo_clear_calls;
static int sortdemo_cursor_calls;
static int sortdemo_config_calls;
static int sortdemo_position_calls;
static int sortdemo_color_calls;
static int sortdemo_bkcolor_calls;
static int sortdemo_outtext_calls;
static int sortdemo_videomode_calls;
static int sortdemo_drawbar_calls;
static int sortdemo_drawbar_last_row;
static int sortdemo_drawtime_calls;
static int sortdemo_drawtime_last_row;
static int sortdemo_beep_calls;
static int sortdemo_beep_last_frequency;
static int sortdemo_beep_last_duration;
static int sortdemo_sleep_calls;
static clock_t sortdemo_sleep_last_wait;
static const char *sortdemo_key_input;
static int sortdemo_key_index;
static int sortdemo_key_calls;

static int sortdemo_selftest_getch( void );
#define getch sortdemo_selftest_getch

typedef struct videoconfig
{
    int monitor;
    int mode;
} videoconfig;

#define _MONO 0
#define _TEXTBW40 1
#define _TEXTBW80 2
#define _GCLEARSCREEN 0
#define _GCURSOROFF 0
#define _GCURSORON 1
#define _DEFAULTMODE 0

static int _settextrows( int rows )
{
    sortdemo_textrows_calls++;
    return 0;
}

static void _clearscreen( int flags )
{
    sortdemo_clear_calls++;
    (void)flags;
}

static void _displaycursor( int state )
{
    sortdemo_cursor_calls++;
    (void)state;
}

static int _getvideoconfig( videoconfig *config )
{
    sortdemo_config_calls++;
    if( config != 0 )
    {
        config->monitor = _MONO;
        config->mode = _TEXTBW80;
    }
    return 0;
}

static int _settextposition( int row, int col )
{
    sortdemo_position_calls++;
    (void)row;
    (void)col;
    return 0;
}

static int _settextcolor( int color )
{
    sortdemo_color_calls++;
    (void)color;
    return 0;
}

static void _setbkcolor( long color )
{
    sortdemo_bkcolor_calls++;
    (void)color;
}

static int _outtext( const char *text )
{
    sortdemo_outtext_calls++;
    (void)text;
    return 0;
}

static int _setvideomode( int mode )
{
    sortdemo_videomode_calls++;
    (void)mode;
    return 0;
}
#else
#include <GRAPH.H>          // _outtext, _settextcolor, _settextposition
#endif

enum BOOL { FALSE, TRUE };

/* Structure type for colored bars */
typedef struct _BAR
{
    char len;
    char clr;
} BAR;

/* Structure type for screen cells */
typedef struct _CELL
{
    char chChar;
    char chAttr;
} CELL;

/* Function prototypes */
#if defined(SORTDEMO_FUNCTION_SELFTEST)
int main( void  );
#else
void main( void  );
#endif
void Cls( void  );
void InitMenu( void  );             // Menu Functions
void DrawFrame( int iTop, int Left, int Width, int Height );
void RunMenu( void  );
void DrawTime( int iCurrentRow );
void InitBars( void  );             // Bar functions
void ReInitBars( void  );
void DrawBar( int iRow );
void SwapBars( int iRow1, int iRow2 );
void Swaps( BAR *one, BAR *two );
void InsertionSort( void  );        // Sort functions
void BubbleSort( void  );
void HeapSort( void  );
void PercolateUp( int iMaxLevel );
void PercolateDown( int iMaxLevel );
void ExchangeSort( void  );
void ShellSort( void  );
void QuickSort( int iLow, int iHigh );
void Beep( int frequency, int duration );
void Sleep( clock_t wait );

/* Macro */
#define GetRandom( min, max ) ((rand() % (int)(((max) + 1) - (min))) + (min))
#define _outtextxy( ach, x, y )   { _settextposition( y, x ); \
                                    _outtext( ach ); }

/* Constants */
#define ESC        27
#define BLANK      32
#define BLOCK      223
#define TOP        1
#define FIRSTMENU  (TOP + 6)
#define LEFTCOLUMN 48
#define PROMPTPOS  27
#define WIDTH      (80 - LEFTCOLUMN)
#define HEIGHT     (cszMenu + 2)
#define MENUCOLOR  15
#define BLANKCOLOR 7
#define BACKCOLOR  0L
#define PAUSELIMIT 900

/* Global variables */
clock_t clStart, clFinish, clPause = 30L;
int fSound, iCurChoice, iSwaps, iCompares, cRow;

BAR abarWork[43], abarPerm[43]; // Temporary and permanent sort arrays

char *aszMenu[] =
{
    "",
    "       C Sorting Demo",
    "",
    "              Time  Swap  Comp",
    "",
    "Insertion",
    "Bubble",
    "Heap",
    "Exchange",
    "Shell",
    "Quick",
    "",
    "Toggle Sound: ",
    "",
    "Pause Factor: ",
    "<   (Slower)",
    ">   (Faster)",
    "",
    "Type first character of",
    "choice ( I B H E S Q T < > )",
    "or ESC key to end program: "
    "",
};
int cszMenu = sizeof( aszMenu ) / sizeof( aszMenu[0] );

#ifdef SORTDEMO_FUNCTION_SELFTEST
enum SORTDEMO_SELFTEST_RESULT
{
    SORTDEMO_SELFTEST_ROWS = 5,
    SORTDEMO_FAIL_INITMENU = 1,
    SORTDEMO_FAIL_DRAWFRAME = 2,
    SORTDEMO_FAIL_RUNMENU = 3,
    SORTDEMO_FAIL_DRAWTIME = 4,
    SORTDEMO_FAIL_INITBARS = 5,
    SORTDEMO_FAIL_REINITBARS = 6,
    SORTDEMO_FAIL_DRAWBAR = 7,
    SORTDEMO_FAIL_SWAPBARS = 8,
    SORTDEMO_FAIL_SWAPS = 9,
    SORTDEMO_FAIL_INSERTIONSORT = 10,
    SORTDEMO_FAIL_BUBBLESORT = 11,
    SORTDEMO_FAIL_HEAPSORT = 12,
    SORTDEMO_FAIL_PERCOLATEUP = 13,
    SORTDEMO_FAIL_PERCOLATEDOWN = 14,
    SORTDEMO_FAIL_EXCHANGESORT = 15,
    SORTDEMO_FAIL_SHELLSORT = 16,
    SORTDEMO_FAIL_QUICKSORT = 17,
    SORTDEMO_FAIL_BEEP = 18,
    SORTDEMO_FAIL_SLEEP = 19,
    SORTDEMO_SELFTEST_SUCCESS_EXIT = 255
};

static void sortdemo_reset_observation( void )
{
    sortdemo_textrows_calls = 0;
    sortdemo_clear_calls = 0;
    sortdemo_cursor_calls = 0;
    sortdemo_config_calls = 0;
    sortdemo_position_calls = 0;
    sortdemo_color_calls = 0;
    sortdemo_bkcolor_calls = 0;
    sortdemo_outtext_calls = 0;
    sortdemo_videomode_calls = 0;
    sortdemo_drawbar_calls = 0;
    sortdemo_drawbar_last_row = -1;
    sortdemo_drawtime_calls = 0;
    sortdemo_drawtime_last_row = -1;
    sortdemo_beep_calls = 0;
    sortdemo_beep_last_frequency = 0;
    sortdemo_beep_last_duration = 0;
    sortdemo_sleep_calls = 0;
    sortdemo_sleep_last_wait = 0;
    sortdemo_key_input = "";
    sortdemo_key_index = 0;
    sortdemo_key_calls = 0;
}

static void sortdemo_set_keys( const char *keys )
{
    sortdemo_key_input = keys;
    sortdemo_key_index = 0;
    sortdemo_key_calls = 0;
}

static int sortdemo_selftest_getch( void )
{
    int ch;

    sortdemo_key_calls++;
    ch = ESC;
    if( sortdemo_key_input != 0 && sortdemo_key_input[sortdemo_key_index] != '\0' )
    {
        ch = sortdemo_key_input[sortdemo_key_index];
        sortdemo_key_index++;
    }
    return ch;
}

static void sortdemo_set_bar( BAR *bar, int len, int clr )
{
    bar->len = (char)len;
    bar->clr = (char)clr;
}

static void sortdemo_set_work_lengths( int len0, int len1, int len2, int len3, int len4 )
{
    cRow = SORTDEMO_SELFTEST_ROWS;
    sortdemo_set_bar( &abarWork[0], len0, 1 );
    sortdemo_set_bar( &abarWork[1], len1, 2 );
    sortdemo_set_bar( &abarWork[2], len2, 3 );
    sortdemo_set_bar( &abarWork[3], len3, 4 );
    sortdemo_set_bar( &abarWork[4], len4, 5 );
}

static void sortdemo_init_test_rows( void )
{
    cRow = SORTDEMO_SELFTEST_ROWS;
    clPause = 30L;
    fSound = FALSE;

    sortdemo_set_bar( &abarPerm[0], 5, 1 );
    sortdemo_set_bar( &abarPerm[1], 3, 2 );
    sortdemo_set_bar( &abarPerm[2], 4, 3 );
    sortdemo_set_bar( &abarPerm[3], 1, 4 );
    sortdemo_set_bar( &abarPerm[4], 2, 5 );
}

static int sortdemo_check_work_lengths( int len0, int len1, int len2, int len3, int len4 )
{
    return ( (int)abarWork[0].len == len0 &&
             (int)abarWork[1].len == len1 &&
             (int)abarWork[2].len == len2 &&
             (int)abarWork[3].len == len3 &&
             (int)abarWork[4].len == len4 );
}

static int sortdemo_check_bars_equal( int start, int count, const BAR *expected )
{
    int idx;

    for( idx = 0; idx < count; idx++ )
    {
        if( (int)abarWork[start + idx].len != (int)expected[idx].len )
            return 0;
        if( (int)abarWork[start + idx].clr != (int)expected[idx].clr )
            return 0;
    }
    return 1;
}

static int sortdemo_is_non_decreasing_len( void )
{
    int idx;

    for( idx = 1; idx < cRow; idx++ )
    {
        if( (int)abarWork[idx - 1].len > (int)abarWork[idx].len )
            return 0;
    }
    return 1;
}

static int sortdemo_perm_lengths_are_valid( void )
{
    int idx;
    int len;
    int seen[44];

    for( idx = 0; idx < 44; idx++ )
        seen[idx] = 0;
    for( idx = 0; idx < cRow; idx++ )
    {
        len = (int)abarPerm[idx].len;
        if( len < 1 || len > cRow )
            return 0;
        if( (int)abarPerm[idx].clr != BLANKCOLOR )
            return 0;
        seen[len]++;
    }
    for( idx = 1; idx <= cRow; idx++ )
    {
        if( seen[idx] != 1 )
            return 0;
    }
    return 1;
}

static int sortdemo_work_equals_perm( void )
{
    int idx;

    for( idx = 0; idx < cRow; idx++ )
    {
        if( (int)abarWork[idx].len != (int)abarPerm[idx].len )
            return 0;
        if( (int)abarWork[idx].clr != (int)abarPerm[idx].clr )
            return 0;
    }
    return 1;
}

static int sortdemo_test_initmenu( void )
{
    cRow = SORTDEMO_SELFTEST_ROWS;
    fSound = TRUE;
    clPause = 30L;
    sortdemo_reset_observation();

    InitMenu();
    if( sortdemo_color_calls == 0 || sortdemo_bkcolor_calls == 0 )
        return SORTDEMO_FAIL_INITMENU;
    if( sortdemo_outtext_calls <= cszMenu )
        return SORTDEMO_FAIL_INITMENU;
    if( sortdemo_position_calls != sortdemo_outtext_calls )
        return SORTDEMO_FAIL_INITMENU;
    return 0;
}

static int sortdemo_test_drawframe( void )
{
    sortdemo_reset_observation();

    DrawFrame( 1, 2, 5, 3 );
    if( sortdemo_outtext_calls != 4 )
        return SORTDEMO_FAIL_DRAWFRAME;
    if( sortdemo_position_calls != 4 )
        return SORTDEMO_FAIL_DRAWFRAME;
    return 0;
}

static int sortdemo_test_runmenu( void )
{
    sortdemo_init_test_rows();
    fSound = FALSE;
    clPause = 30L;
    sortdemo_reset_observation();
    sortdemo_set_keys( "T><\033" );

    RunMenu();
    if( sortdemo_key_calls != 4 )
        return SORTDEMO_FAIL_RUNMENU;
    if( fSound != TRUE )
        return SORTDEMO_FAIL_RUNMENU;
    if( clPause != 30L )
        return SORTDEMO_FAIL_RUNMENU;
    if( sortdemo_cursor_calls != 8 )
        return SORTDEMO_FAIL_RUNMENU;
    return 0;
}

static int sortdemo_test_drawtime( void )
{
    fSound = FALSE;
    clPause = 42L;
    sortdemo_reset_observation();

    DrawTime( 3 );
    if( sortdemo_drawtime_calls != 1 || sortdemo_drawtime_last_row != 3 )
        return SORTDEMO_FAIL_DRAWTIME;
    if( sortdemo_sleep_calls != 1 || sortdemo_sleep_last_wait != 42L )
        return SORTDEMO_FAIL_DRAWTIME;
    return 0;
}

static int sortdemo_test_initbars( void )
{
    cRow = SORTDEMO_SELFTEST_ROWS;
    sortdemo_reset_observation();

    InitBars();
    if( fSound != TRUE || clPause != 30L )
        return SORTDEMO_FAIL_INITBARS;
    if( sortdemo_config_calls != 1 )
        return SORTDEMO_FAIL_INITBARS;
    if( sortdemo_drawbar_calls != cRow )
        return SORTDEMO_FAIL_INITBARS;
    if( !sortdemo_perm_lengths_are_valid() )
        return SORTDEMO_FAIL_INITBARS;
    if( !sortdemo_work_equals_perm() )
        return SORTDEMO_FAIL_INITBARS;
    return 0;
}

static int sortdemo_test_reinitbars( void )
{
    BAR expected[SORTDEMO_SELFTEST_ROWS];

    sortdemo_init_test_rows();
    sortdemo_reset_observation();
    ReInitBars();

    sortdemo_set_bar( &expected[0], 5, 1 );
    sortdemo_set_bar( &expected[1], 3, 2 );
    sortdemo_set_bar( &expected[2], 4, 3 );
    sortdemo_set_bar( &expected[3], 1, 4 );
    sortdemo_set_bar( &expected[4], 2, 5 );
    if( !sortdemo_check_bars_equal(0, cRow, expected) )
        return SORTDEMO_FAIL_REINITBARS;
    if( sortdemo_drawbar_calls != cRow )
        return SORTDEMO_FAIL_REINITBARS;

    return 0;
}

static int sortdemo_test_drawbar( void )
{
    sortdemo_init_test_rows();
    ReInitBars();
    sortdemo_reset_observation();

    DrawBar( 2 );
    if( sortdemo_drawbar_calls != 1 )
        return SORTDEMO_FAIL_DRAWBAR;
    if( sortdemo_drawbar_last_row != 2 )
        return SORTDEMO_FAIL_DRAWBAR;
    return 0;
}

static int sortdemo_test_swapbars( void )
{
    BAR expected[SORTDEMO_SELFTEST_ROWS];

    sortdemo_init_test_rows();
    ReInitBars();
    sortdemo_reset_observation();

    SwapBars( 1, 2 );
    sortdemo_set_bar( &expected[0], 5, 1 );
    sortdemo_set_bar( &expected[1], 3, 2 );
    sortdemo_set_bar( &expected[2], 4, 3 );
    sortdemo_set_bar( &expected[3], 1, 4 );
    sortdemo_set_bar( &expected[4], 2, 5 );
    if( !sortdemo_check_bars_equal(0, cRow, expected) )
        return SORTDEMO_FAIL_SWAPBARS;
    if( sortdemo_drawbar_calls != 2 || sortdemo_drawbar_last_row != 2 )
        return SORTDEMO_FAIL_SWAPBARS;
    if( sortdemo_drawtime_calls != 1 || sortdemo_drawtime_last_row != 1 )
        return SORTDEMO_FAIL_SWAPBARS;
    return 0;
}

static int sortdemo_test_swaps( void )
{
    BAR expected[SORTDEMO_SELFTEST_ROWS];

    sortdemo_init_test_rows();
    ReInitBars();
    iSwaps = 0;

    Swaps( &abarWork[0], &abarWork[1] );

    sortdemo_set_bar( &expected[0], 3, 2 );
    sortdemo_set_bar( &expected[1], 5, 1 );
    sortdemo_set_bar( &expected[2], 4, 3 );
    sortdemo_set_bar( &expected[3], 1, 4 );
    sortdemo_set_bar( &expected[4], 2, 5 );
    if( !sortdemo_check_bars_equal(0, cRow, expected) )
        return SORTDEMO_FAIL_SWAPS;
    if( iSwaps != 1 )
        return SORTDEMO_FAIL_SWAPS;
    return 0;
}

static int sortdemo_test_percolateup( void )
{
    sortdemo_set_work_lengths( 3, 1, 2, 4, 5 );

    PercolateUp( 3 );
    if( !sortdemo_check_work_lengths( 4, 3, 2, 1, 5 ) )
        return SORTDEMO_FAIL_PERCOLATEUP;
    return 0;
}

static int sortdemo_test_percolatedown( void )
{
    sortdemo_set_work_lengths( 1, 5, 4, 3, 2 );

    PercolateDown( 4 );
    if( !sortdemo_check_work_lengths( 5, 4, 2, 3, 1 ) )
        return SORTDEMO_FAIL_PERCOLATEDOWN;
    return 0;
}

static int sortdemo_test_insertionsort( void )
{
    sortdemo_set_work_lengths( 4, 2, 5, 3, 1 );

    InsertionSort();
    if( !sortdemo_is_non_decreasing_len() )
        return SORTDEMO_FAIL_INSERTIONSORT;
    return 0;
}

static int sortdemo_test_bubblesort( void )
{
    sortdemo_set_work_lengths( 4, 1, 5, 3, 2 );

    BubbleSort();
    if( !sortdemo_is_non_decreasing_len() )
        return SORTDEMO_FAIL_BUBBLESORT;
    return 0;
}

static int sortdemo_test_heapsort( void )
{
    sortdemo_set_work_lengths( 5, 1, 4, 2, 3 );

    HeapSort();
    if( !sortdemo_is_non_decreasing_len() )
        return SORTDEMO_FAIL_HEAPSORT;
    return 0;
}

static int sortdemo_test_exchangesort( void )
{
    sortdemo_set_work_lengths( 5, 4, 3, 2, 1 );

    ExchangeSort();
    if( !sortdemo_is_non_decreasing_len() )
        return SORTDEMO_FAIL_EXCHANGESORT;
    return 0;
}

static int sortdemo_test_shellsort( void )
{
    sortdemo_set_work_lengths( 5, 3, 4, 1, 2 );

    ShellSort();
    if( !sortdemo_is_non_decreasing_len() )
        return SORTDEMO_FAIL_SHELLSORT;
    return 0;
}

static int sortdemo_test_quicksort( void )
{
    sortdemo_set_work_lengths( 2, 5, 1, 4, 3 );

    QuickSort( 0, cRow - 1 );
    if( !sortdemo_is_non_decreasing_len() )
        return SORTDEMO_FAIL_QUICKSORT;
    return 0;
}

static int sortdemo_test_beep( void )
{
    sortdemo_reset_observation();
    Beep( 0, 30 );
    if( sortdemo_beep_calls != 1 || sortdemo_beep_last_frequency != 0 )
        return SORTDEMO_FAIL_BEEP;
    if( sortdemo_beep_last_duration != 30 || sortdemo_sleep_last_wait != 30L )
        return SORTDEMO_FAIL_BEEP;

    sortdemo_reset_observation();
    Beep( 120, 30 );
    if( sortdemo_beep_calls != 1 || sortdemo_beep_last_frequency != 120 )
        return SORTDEMO_FAIL_BEEP;
    if( sortdemo_beep_last_duration != 75 || sortdemo_sleep_last_wait != 75L )
        return SORTDEMO_FAIL_BEEP;
    return 0;
}

static int sortdemo_test_sleep( void )
{
    sortdemo_reset_observation();
    Sleep( 17L );
    if( sortdemo_sleep_calls != 1 )
        return SORTDEMO_FAIL_SLEEP;
    if( sortdemo_sleep_last_wait != 17L )
        return SORTDEMO_FAIL_SLEEP;
    return 0;
}

static int sortdemo_function_selftest( void )
{
    int status;

    status = sortdemo_test_initmenu();
    if( status )
        return status;
    status = sortdemo_test_drawframe();
    if( status )
        return status;
    status = sortdemo_test_runmenu();
    if( status )
        return status;
    status = sortdemo_test_drawtime();
    if( status )
        return status;
    status = sortdemo_test_initbars();
    if( status )
        return status;
    status = sortdemo_test_reinitbars();
    if( status )
        return status;
    status = sortdemo_test_drawbar();
    if( status )
        return status;
    status = sortdemo_test_swapbars();
    if( status )
        return status;
    status = sortdemo_test_swaps();
    if( status )
        return status;
    status = sortdemo_test_insertionsort();
    if( status )
        return status;
    status = sortdemo_test_bubblesort();
    if( status )
        return status;
    status = sortdemo_test_heapsort();
    if( status )
        return status;
    status = sortdemo_test_percolateup();
    if( status )
        return status;
    status = sortdemo_test_percolatedown();
    if( status )
        return status;
    status = sortdemo_test_exchangesort();
    if( status )
        return status;
    status = sortdemo_test_shellsort();
    if( status )
        return status;
    status = sortdemo_test_quicksort();
    if( status )
        return status;
    status = sortdemo_test_beep();
    if( status )
        return status;
    status = sortdemo_test_sleep();
    if( status )
        return status;

    return SORTDEMO_SELFTEST_SUCCESS_EXIT;
}
#endif

#if !defined(SORTDEMO_FUNCTION_SELFTEST)
void main()
#else
int main(void)
#endif
{
#if defined(SORTDEMO_FUNCTION_SELFTEST)
    return sortdemo_function_selftest();
#else
    cRow = _settextrows( 43 );
    _clearscreen( _GCLEARSCREEN );
    _displaycursor( _GCURSOROFF );
    InitBars();
    InitMenu();
    RunMenu();                     // Respond to menu until quit
    _setvideomode( _DEFAULTMODE );
#endif
}


/* InitMenu - Calls the DrawFrame procedure to draw the frame around the
 * sort menu, then prints the different options stored in the menu array.
 */
void InitMenu()
{
    int  i;
    char ach[15];

    _settextcolor( MENUCOLOR );
    _setbkcolor( BACKCOLOR );
    DrawFrame( TOP, LEFTCOLUMN - 3, WIDTH + 3, HEIGHT );
    for( i = 0; i < cszMenu; i++ )
        _outtextxy( aszMenu[i], LEFTCOLUMN, TOP + i + 1 );

    /* Print the current value for Sound. */
    if( fSound )
        strcpy( ach, "ON " );
    else
        strcpy( ach, "OFF" );

    _outtextxy( ach, LEFTCOLUMN + 14, cszMenu - 7 );
    sprintf( ach, "%3.3u", clPause / 30 );
    _outtextxy( ach, LEFTCOLUMN + 14, cszMenu - 5 );

    /* Erase the speed option if the length of the pause is at a limit. */
    strcpy( ach, "            " );
    if( clPause == PAUSELIMIT )
        _outtextxy( ach, LEFTCOLUMN, cszMenu - 4 );
    if( clPause == 0L )
        _outtextxy( ach, LEFTCOLUMN, cszMenu - 3 );
}


/* DrawFrame - Draws a rectangular frame using the double-line box
 * characters. The parameters iTop, iLeft, iWidth, and iHeight are
 * the row and column arguments for the upper-left and lower-right
 * corners of the frame.
 */
void DrawFrame( int iTop, int iLeft, int iWidth, int iHeight )
{
    enum { ULEFT = 201, URIGHT = 187,
           LLEFT = 200, LRIGHT = 188, VERTICAL = 186, HORIZONTAL = 205
         };
    int iRow;
    char achTmp[80];

    memset( achTmp, HORIZONTAL, iWidth );
    achTmp[0] = ULEFT;
    achTmp[iWidth - 1] = URIGHT;
    achTmp[iWidth] = '\0';
    _outtextxy( achTmp, iLeft, iTop );

    memset( achTmp, BLANK, iWidth );
    achTmp[0] = VERTICAL;
    achTmp[iWidth - 1] = VERTICAL;
    for(  iRow = iTop + 1; iRow <= iHeight; iRow++ )
        _outtextxy( achTmp, iLeft, iRow );

    memset( achTmp, HORIZONTAL, iWidth );
    achTmp[0] = LLEFT;
    achTmp[iWidth - 1] = LRIGHT;
    _outtextxy( achTmp, iLeft, iTop + iHeight );
}


/* RunMenu - The RunMenu procedure first calls the ReInitBars
 * procedure to make sure the abarWork is in its unsorted form, then
 * prompts the user to make one of the following choices:
 *
 *  - Run one of the sorting algorithms
 *  - Toggle sound on or off
 *  - Increase or decrease speed
 *  - End the program
 */
void RunMenu()
{
    char    ch;

    while( TRUE )
    {
        iSwaps = iCompares = 0;
        _settextposition( TOP + cszMenu, LEFTCOLUMN + PROMPTPOS );
        _displaycursor( _GCURSORON );
        ch = getch();
        _displaycursor( _GCURSOROFF );

        /* Branch to the appropriate procedure depending on the key. */
        switch( toupper( ch ) )
        {
            case 'I':
                iCurChoice = 0;
                ReInitBars();
                InsertionSort();
                DrawTime( 0 );   // Print final time
                break;
            case 'B':
                iCurChoice = 1;
                ReInitBars();
                BubbleSort();
                DrawTime( 0 );
                break;

            case 'H':
                iCurChoice = 2;
                ReInitBars();
                HeapSort();
                DrawTime( 0 );
                break;

            case 'E':
                iCurChoice = 3;
                ReInitBars();
                ExchangeSort();
                DrawTime( 0 );
                break;

            case 'S':
                iCurChoice = 4;
                ReInitBars();
                ShellSort();
                DrawTime( 0 );
                break;

            case 'Q':
                iCurChoice = 5;
                ReInitBars();
                QuickSort( 0, cRow );
                DrawTime( 0 );
                break;

            case '>':
                /* Decrease pause length to speed up sorting time, then
                 * redraw the menu to clear any timing results (since
                 * they won't compare with future results).
                 */
                if( clPause )
                    clPause -= 30L;
                InitMenu();
                break;

            case '<':
                /* Increase pause length to slow down sorting time. */
                if( clPause <= 900L )
                    clPause += 30L;
                InitMenu();
                break;

            case 'T':
                fSound = !fSound;
                InitMenu();
                break;

            case ESC:
                return;

            default:        // Unknown key ignored
                break;
        }
    }
}


/* DrawTime - Prints seconds elapsed since the given sorting routine
 * started. Note that this time includes both the time it takes to redraw
 * the bars plus the pause while Beep plays a note, and thus is not an
 * accurate indication of sorting speed.
 */
void DrawTime( int iCurrentRow )
{
#ifdef SORTDEMO_FUNCTION_SELFTEST
    sortdemo_drawtime_calls++;
    sortdemo_drawtime_last_row = iCurrentRow;
    if( fSound )
    {
        Beep( 60 * iCurrentRow, 75 );
        Sleep( clPause - 75L );
    }
    else
        Sleep( clPause );
#else
    char achTiming[80];

    _settextcolor( MENUCOLOR );
    clFinish = clock();

    sprintf( achTiming, "%7.i  %4.i  %4.i",
             /*(float)*/(clFinish - clStart) / CLOCKS_PER_SEC,
             iSwaps, iCompares );

    /* Print the number of seconds elapsed */
    _outtextxy( achTiming, LEFTCOLUMN + 11, FIRSTMENU + iCurChoice );
    if( fSound )
    {
        Beep( 60 * iCurrentRow, 75 );   // Play note
        Sleep( clPause - 75L );         // Pause adjusted for note duration
    }
    else
        Sleep( clPause );               // Pause
#endif
}


/* InitBars - Initializes the bar arrays and the menu box.
 */
void InitBars()
{
    struct videoconfig vc;
    int aTemp[43], iRow, iRowMax, iRand, iColorMax, iLength;

    /* Seed the random-number generator. */
    srand( (unsigned)time( NULL ) );
    fSound = TRUE;
    clPause = 30L;

    /* If monochrome or color burst disabled, use one color */
    _getvideoconfig( &vc );
    if( (vc.monitor == _MONO) || (vc.mode == _TEXTBW80) ||
                                 (vc.mode == _TEXTBW40) )
        iColorMax = 1;
    else
        iColorMax = 15;

    /* Randomize an array of rows. */
    for( iRow = 0; iRow < cRow; iRow++ )
        aTemp[iRow] = iRow + 1;
    iRowMax = cRow - 1;
    for( iRow = 0; iRow < cRow; iRow++ )
    {
        /* Find a random element in aTemp between 0 and iRowMax,
         * then assign the value in that element to iLength.
         */
        iRand = GetRandom( 0, iRowMax );
        iLength = aTemp[iRand];

        /* Overwrite the value in aTemp[iRand] with the value in
         * aTemp[iRowMax] so the value in aTemp[iRand] is
         * chosen only once.
         */
        aTemp[iRand] = aTemp[iRowMax];

        /* Decrease the value of iRowMax so that aTemp[iRowMax] can't
         * be chosen on the next pass through the loop.
         */
        --iRowMax;
        abarPerm[iRow].len = iLength;
        if( iColorMax == 1 )
            abarPerm[iRow].clr = BLANKCOLOR;
        else
            abarPerm[iRow].clr = iLength % iColorMax + 1;
    }

    /* Assign permanent sort values to temporary and draw unsorted bars. */
    ReInitBars();
}


/* ReInitBars - Restores the array abarWork to its original unsorted
 * state and draws the unsorted bars.
 */
void ReInitBars()
{
    int iRow;

    clStart = clock();
    for( iRow = 0; iRow < cRow; iRow++ )
    {
        abarWork[iRow] = abarPerm[iRow];
        DrawBar( iRow );
    }
}


/* DrawBar - Prints a bar at a specified row by first blanking the
 * old bar, then drawing a new bar having the length and color given in
 * the work array.
 */
void DrawBar( int iRow )
{
#ifdef SORTDEMO_FUNCTION_SELFTEST
    sortdemo_drawbar_calls++;
    sortdemo_drawbar_last_row = iRow;
#else
    int  cSpace;
    char achT[43];

    memset( achT, BLOCK, abarWork[iRow].len );
    cSpace = cRow - abarWork[iRow].len;
    memset( achT + abarWork[iRow].len, ' ', cSpace );
    achT[cRow] = '\0';
    _settextcolor( abarWork[iRow].clr );
    _outtextxy( achT, 0, iRow + 1 );
#endif
}


/* SwapBars - Calls DrawBar twice to switch the two bars in iRow1 and
 * iRow2, then calls DrawTime to update the time.
 */
void SwapBars( int iRow1, int iRow2 )
{
    DrawBar( iRow1 );
    DrawBar( iRow2 );
    DrawTime( iRow1 );
}


/* Swaps - Exchanges two bar structures.
 */
void Swaps( BAR *bar1, BAR *bar2 )
{
    BAR barTmp;

    ++iSwaps;
    barTmp = *bar1;
    *bar1  = *bar2;
    *bar2  = barTmp;
}


/* InsertionSort - InsertionSort compares the length of each element
 * with the lengths of all the preceding elements. When the appropriate
 * place for the new element is found, the element is inserted and
 * all the other elements are moved down one place.
 */
void InsertionSort()
{
    BAR barTemp;
    int iRow, iRowTmp, iLength;

    /* Start at the top. */
    for( iRow = 0; iRow < cRow; iRow++ )
    {
        barTemp = abarWork[iRow];
        iLength = barTemp.len;

        /* As long as the length of the temporary element is greater than
         * the length of the original, keep shifting the elements down.
         */
        for( iRowTmp = iRow; iRowTmp; iRowTmp-- )
        {
            iCompares++;
            if( abarWork[iRowTmp - 1].len > iLength )
            {
                ++iSwaps;
                abarWork[iRowTmp] = abarWork[iRowTmp - 1];
                DrawBar( iRowTmp );         // Print the new bar
                DrawTime( iRowTmp );        // Print the elapsed time

            }
            else                            // Otherwise, exit
                break;
        }

        /* Insert the original bar in the temporary position. */
        abarWork[iRowTmp] = barTemp;
        DrawBar( iRowTmp );
        DrawTime( iRowTmp );
    }
}


/* BubbleSort - BubbleSort cycles through the elements, comparing
 * adjacent elements and swapping pairs that are out of order. It
 * continues to do this until no out-of-order pairs are found.
 */
void BubbleSort()
{
    int iRow, iSwitch, iLimit = cRow;

    /* Move the longest bar down to the bottom until all are in order. */
    do
    {
        iSwitch = 0;
        for( iRow = 0; iRow < iLimit; iRow++ )
        {
            /* If two adjacent elements are out of order, swap their values
             * and redraw those two bars.
             */
            iCompares++;
            if( abarWork[iRow].len > abarWork[iRow + 1].len )
            {
                Swaps( &abarWork[iRow], &abarWork[iRow + 1] );
                SwapBars( iRow, iRow + 1 );
                iSwitch = iRow;
            }
        }

        /* Sort on next pass only to where the last switch was made. */
        iLimit = iSwitch;
    } while( iSwitch );
}


/* HeapSort - HeapSort (also called TreeSort) works by calling
 * PercolateUp and PercolateDown. PercolateUp organizes the elements
 * into a "heap" or "tree," which has the properties shown below:
 *
 *                             element[1]
 *                           /            \
 *                element[2]                element[3]
 *               /          \              /          \
 *         element[4]     element[5]   element[6]    element[7]
 *         /        \     /        \   /        \    /        \
 *        ...      ...   ...      ... ...      ...  ...      ...
 *
 *
 * Each "parent node" is greater than each of its "child nodes"; for
 * example, element[1] is greater than element[2] or element[3];
 * element[4] is greater than element[5] or element[6], and so forth.
 * Therefore, once the first loop in HeapSort is finished, the
 * largest element is in element[1].
 *
 * The second loop rebuilds the heap (with PercolateDown), but starts
 * at the top and works down, moving the largest elements to the bottom.
 * This has the effect of moving the smallest elements to the top and
 * sorting the heap.
 */
void HeapSort()
{
    int i;

    for( i = 1; i < cRow; i++ )
        PercolateUp( i );

    for( i = cRow - 1; i > 0; i-- )
    {
        Swaps( &abarWork[0], &abarWork[i] );
        SwapBars( 0, i );
        PercolateDown( i - 1 );
    }
}


/* PercolateUp - Converts elements into a "heap" with the largest
 * element at the top (see the diagram above).
 */
void PercolateUp( int iMaxLevel )
{
    int i = iMaxLevel, iParent;

    /* Move the value in abarWork[iMaxLevel] up the heap until it has
     * reached its proper node (that is, until it is greater than either
     * of its child nodes, or until it has reached 1, the top of the heap).
     */
    while( i )
    {
        iParent = i / 2;    // Get the subscript for the parent node

        iCompares++;
        if( abarWork[i].len > abarWork[iParent].len )
        {
            /* The value at the current node is bigger than the value at
             * its parent node, so swap these two array elements.
             */
            Swaps( &abarWork[iParent], &abarWork[i] );
            SwapBars( iParent, i );
            i = iParent;
        }
        else
            /* Otherwise, the element has reached its proper place in the
             * heap, so exit this procedure.
             */
            break;
    }
}


/* PercolateDown - Converts elements to a "heap" with the largest elements
 * at the bottom. When this is done to a reversed heap (largest elements
 * at top), it has the effect of sorting the elements.
 */
void PercolateDown( int iMaxLevel )
{
    int iChild, i = 0;

    /* Move the value in abarWork[0] down the heap until it has reached
     * its proper node (that is, until it is less than its parent node
     * or until it has reached iMaxLevel, the bottom of the current heap).
     */
    while( TRUE )
    {
        /* Get the subscript for the child node. */
        iChild = 2 * i;

        /* Reached the bottom of the heap, so exit this procedure. */
        if( iChild > iMaxLevel )
            break;

        /* If there are two child nodes, find out which one is bigger. */
        if( iChild + 1 <= iMaxLevel )
        {
            iCompares++;
            if( abarWork[iChild + 1].len > abarWork[iChild].len )
                iChild++;
        }

        iCompares++;
        if( abarWork[i].len < abarWork[iChild].len )
        {
            /* Move the value down since it is still not bigger than
             * either one of its children.
             */
            Swaps( &abarWork[i], &abarWork[iChild] );
            SwapBars( i, iChild );
            i = iChild;
        }
        else
            /* Otherwise, abarWork has been restored to a heap from 1 to
             * iMaxLevel, so exit.
             */
            break;
    }
}


/* ExchangeSort - The ExchangeSort compares each element--starting with
 * the first--with every following element. If any of the following
 * elements is smaller than the current element, it is exchanged with
 * the current element and the process is repeated for the next element.
 */
void ExchangeSort()
{
    int iRowCur, iRowMin, iRowNext;

    for( iRowCur = 0; iRowCur < cRow; iRowCur++ )
    {
        iRowMin = iRowCur;
        for( iRowNext = iRowCur; iRowNext < cRow; iRowNext++ )
        {
            iCompares++;
            if( abarWork[iRowNext].len < abarWork[iRowMin].len )
            {
                iRowMin = iRowNext;
                DrawTime( iRowNext );
            }
        }

        /* If a row is shorter than the current row, swap those two
         * array elements.
         */
        if( iRowMin > iRowCur )
        {
            Swaps( &abarWork[iRowCur], &abarWork[iRowMin] );
            SwapBars( iRowCur, iRowMin );
        }
    }
}


/* ShellSort - ShellSort is similar to the BubbleSort. However, it
 * begins by comparing elements that are far apart (separated by the
 * value of the iOffset variable, which is initially half the distance
 * between the first and last element), then comparing elements that
 * are closer together. When iOffset is one, the last iteration of
 * is merely a bubble sort.
 */
void ShellSort()
{
    int iOffset, iSwitch, iLimit, iRow;

    /* Set comparison offset to half the number of bars. */
    iOffset = cRow / 2;

    while( iOffset )
    {
        /* Loop until offset gets to zero. */
        iLimit = cRow - iOffset;
        do
        {
            iSwitch = FALSE;     // Assume no switches at this offset.

            /* Compare elements and switch ones out of order. */
            for( iRow = 0; iRow <= iLimit; iRow++ )
            {
                iCompares++;
                if( abarWork[iRow].len > abarWork[iRow + iOffset].len )
                {
                    Swaps( &abarWork[iRow], &abarWork[iRow + iOffset] );
                    SwapBars( iRow, iRow + iOffset );
                    iSwitch = iRow;
                }
            }

            /* Sort on next pass only to where last switch was made. */
            iLimit = iSwitch - iOffset;
        } while( iSwitch );

        /* No switches at last offset, try one half as big. */
        iOffset = iOffset / 2;
    }
}


/* QuickSort - QuickSort works by picking a random "pivot" element,
 * then moving every element that is bigger to one side of the pivot,
 * and every element that is smaller to the other side. QuickSort is
 * then called recursively with the two subdivisions created by the pivot.
 * Once the number of elements in a subdivision reaches two, the recursive
 * calls end and the array is sorted.
 */
void QuickSort( int iLow, int iHigh )
{
    int iUp, iDown, iBreak;

    if( iLow < iHigh )
    {
        /* Only two elements in this subdivision; swap them if they are
         * out of order, then end recursive calls.
         */
        if( (iHigh - iLow) == 1 )
        {
            iCompares++;
            if( abarWork[iLow].len > abarWork[iHigh].len )
            {
                Swaps( &abarWork[iLow], &abarWork[iHigh] );
                SwapBars( iLow, iHigh );
            }
        }
        else
        {
            iBreak = abarWork[iHigh].len;
            do
            {
                /* Move in from both sides towards the pivot element. */
                iUp = iLow;
                iDown = iHigh;
                iCompares++;
                while( (iUp < iDown) && (abarWork[iUp].len <= iBreak) )
                    iUp++;
                iCompares++;
                while( (iDown > iUp) && (abarWork[iDown].len >= iBreak) )
                    iDown--;
                /* If we haven't reached the pivot, it means that two
                 * elements on either side are out of order, so swap them.
                 */
                if( iUp < iDown )
                {
                    Swaps( &abarWork[iUp], &abarWork[iDown] );
                    SwapBars( iUp, iDown );
                }
            } while ( iUp < iDown );

            /* Move pivot element back to its proper place in the array. */
            Swaps( &abarWork[iUp], &abarWork[iHigh] );
            SwapBars( iUp, iHigh );

            /* Recursively call the QuickSort procedure (pass the smaller
             * subdivision first to use less stack space).
             */
            if( (iUp - iLow) < (iHigh - iUp) )
            {
                QuickSort( iLow, iUp - 1 );
                QuickSort( iUp + 1, iHigh );
            }
            else
            {
                QuickSort( iUp + 1, iHigh );
                QuickSort( iLow, iUp - 1 );
            }
        }
    }
}

/* Beep - Sounds the speaker for a time specified in microseconds by
 * duration at a pitch specified in hertz by frequency.
 */
void Beep( int frequency, int duration )
{
#ifdef SORTDEMO_FUNCTION_SELFTEST
    if( frequency && duration < 75 )
        duration = 75;
    sortdemo_beep_calls++;
    sortdemo_beep_last_frequency = frequency;
    sortdemo_beep_last_duration = duration;
    Sleep( (clock_t)duration );
#else
/* Use system call for OS/2 */
#if defined( OS2 )
#define INCL_NOCOMMON
#define INCL_NOPM
#define INCL_DOSPROCESS
#include <os2.h>
    DosBeep( frequency, duration );
#else
/* Define procedure for DOS */
    int control;

    /* If frequency is 0, Beep doesn't try to make a sound. It
     * just sleeps for the duration.
     */
    if( frequency )
    {
        /* 75 is about the shortest reliable duration of a sound. */
        if( duration < 75 )
            duration = 75;

        /* Prepare timer by sending 10111100 to port 43. */
        outp( 0x43, 0xb6 );

        /* Divide input frequency by timer ticks per second and
         * write (byte by byte) to timer.
         */
        frequency = (unsigned)(1193180L / frequency);
        outp( 0x42, (char)frequency );
        outp( 0x42, (char)(frequency >> 8) );

        /* Save speaker control byte. */
        control = inp( 0x61 );

        /* Turn on the speaker (with bits 0 and 1). */
        outp( 0x61, control | 0x3 );
    }

    Sleep( (clock_t)duration );

    /* Turn speaker back on if necessary. */
    if( frequency )
        outp( 0x61, control );

#endif              /* DOS version */

#endif              /* SORTDEMO_FUNCTION_SELFTEST */
}

/* Pauses for a specified number of microseconds. */
void Sleep( clock_t wait )
{
#ifdef SORTDEMO_FUNCTION_SELFTEST
    sortdemo_sleep_calls++;
    sortdemo_sleep_last_wait = wait;
#else
    clock_t goal;

    goal = wait + clock();
    while( goal >= clock() )
        ;
#endif
}
