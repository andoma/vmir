#ifdef __cplusplus
extern "C"
{
#endif

double floor(double x);
float floorf(float x);

double sin(double x);
float sinf(float x);

double cos(double x);
float cosf(float x);

double pow(double x, double y);
float powf(float x, float y);

double fabs(double x);
float fabsf(float x);

double fmod(double x, double y);
float fmodf(float x, float y);

double log10(double x);
float log10f(float x);

double log(double x);
float logf(float x);

double sqrt(double x);
float sqrtf(float x);

double ceil(double x);
float ceilf(float x);

double round(double x);
float roundf(float x);

double ldexp(double x, int exp);
float ldexpf(float x, int exp);

double exp(double x);
float expf(float x);


# define M_E		2.7182818284590452354	/* e */
# define M_LOG2E	1.4426950408889634074	/* log_2 e */
# define M_LOG10E	0.43429448190325182765	/* log_10 e */
# define M_LN2		0.69314718055994530942	/* log_e 2 */
# define M_LN10		2.30258509299404568402	/* log_e 10 */
# define M_PI		3.14159265358979323846	/* pi */
# define M_PI_2		1.57079632679489661923	/* pi/2 */
# define M_PI_4		0.78539816339744830962	/* pi/4 */
# define M_1_PI		0.31830988618379067154	/* 1/pi */
# define M_2_PI		0.63661977236758134308	/* 2/pi */
# define M_2_SQRTPI	1.12837916709551257390	/* 2/sqrt(pi) */
# define M_SQRT2	1.41421356237309504880	/* sqrt(2) */
# define M_SQRT1_2	0.70710678118654752440	/* 1/sqrt(2) */


#ifdef __cplusplus
}
#endif
