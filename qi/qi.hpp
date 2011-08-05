/*
** Author(s):
**  - Cedric GESTES <gestes@aldebaran-robotics.com>
**
** Copyright (C) 2011 Aldebaran Robotics
*/

#ifndef   	QI_HPP_
# define   	QI_HPP_


///toto
namespace qi {

  QI_API void init(int argc, char *argv[]);
  QI_API int argc();
  QI_API const char** argv();
  QI_API const char *program();

  typedef std::codecvt<wchar_t, char, std::mbstate_t> codecvt_type;
  QI_API const codecvt_type &unicodeFacet();

}

#endif	    /* !QI_PP_ */
