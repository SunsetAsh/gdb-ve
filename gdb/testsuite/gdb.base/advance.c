
static int x;

int foo (int a)
{
  int b = a + 10;
  return b;
}

int bar (int y)
{
  int z = y + 20;
  return z;
}

int func2 ()
{
  x = 6;
#ifdef VEOS
  return 0;
#endif
}

void func()
{
  x = x + 5;
  func2 ();
}

int func3 ()
{
  x = 4;
#ifdef VEOS
  return 0;
#endif
}

void marker1 ()
{
}

int
main ()
{
  int result;
  int b, c;
  c = 5;
  b = 3;    /* advance this location */
    
#ifdef VEOS
  func (); /* stop here after leaving current frame */
#else
  func (c); /* stop here after leaving current frame */
#endif
  marker1 (); /* stop here after leaving current frame */
  func3 (); /* break here */
  result = bar (b + foo (c));
  return 0; /* advance malformed */
}

