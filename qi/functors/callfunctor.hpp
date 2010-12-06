#pragma once
/*
*  Author(s):
*  - Chris  Kilner <ckilner@aldebaran-robotics.com>
*  - Cedric Gestes <gestes@aldebaran-robotics.com>
*
*  Copyright (C) 2010 Aldebaran Robotics
*/


#ifndef _QI_FUNCTORS_CALLFUNCTOR_HPP_
#define _QI_FUNCTORS_CALLFUNCTOR_HPP_

#include <qi/functors/functor.hpp>

namespace qi
{

  template <typename R>
  R callFunctor(Functor *f) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    f->call(args, ret);
    R r;
    qi::serialization::serialize<R>::read(ret, r);
    return r;
  }

  void callVoidFunctor(Functor *f) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    f->call(args, ret);
  }


  template <typename R, typename P0>
  R callFunctor(Functor *f, const P0 &p0) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    f->call(args, ret);
    R r;
    qi::serialization::serialize<R>::read(ret, r);
    return r;
  }

  template <typename P0>
  void callVoidFunctor(Functor *f, const P0 &p0) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    f->call(args, ret);
  }


  template <typename R, typename P0, typename P1>
  R callFunctor(Functor *f, const P0 &p0, const P1 &p1) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    f->call(args, ret);
    R r;
    qi::serialization::serialize<R>::read(ret, r);
    return r;
  }

  template <typename P0, typename P1>
  void callVoidFunctor(Functor *f, const P0 &p0, const P1 &p1) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    f->call(args, ret);
  }


  template <typename R, typename P0, typename P1, typename P2>
  R callFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    f->call(args, ret);
    R r;
    qi::serialization::serialize<R>::read(ret, r);
    return r;
  }

  template <typename P0, typename P1, typename P2>
  void callVoidFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    f->call(args, ret);
  }


  template <typename R, typename P0, typename P1, typename P2, typename P3>
  R callFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    f->call(args, ret);
    R r;
    qi::serialization::serialize<R>::read(ret, r);
    return r;
  }

  template <typename P0, typename P1, typename P2, typename P3>
  void callVoidFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    f->call(args, ret);
  }


  template <typename R, typename P0, typename P1, typename P2, typename P3, typename P4>
  R callFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    qi::serialization::serialize<P4>::write(args, p4);
    f->call(args, ret);
    R r;
    qi::serialization::serialize<R>::read(ret, r);
    return r;
  }

  template <typename P0, typename P1, typename P2, typename P3, typename P4>
  void callVoidFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    qi::serialization::serialize<P4>::write(args, p4);
    f->call(args, ret);
  }


  template <typename R, typename P0, typename P1, typename P2, typename P3, typename P4, typename P5>
  R callFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    qi::serialization::serialize<P4>::write(args, p4);
    qi::serialization::serialize<P5>::write(args, p5);
    f->call(args, ret);
    R r;
    qi::serialization::serialize<R>::read(ret, r);
    return r;
  }

  template <typename P0, typename P1, typename P2, typename P3, typename P4, typename P5>
  void callVoidFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    qi::serialization::serialize<P4>::write(args, p4);
    qi::serialization::serialize<P5>::write(args, p5);
    f->call(args, ret);
  }


  template <typename R, typename P0, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6>
  R callFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    qi::serialization::serialize<P4>::write(args, p4);
    qi::serialization::serialize<P5>::write(args, p5);
    qi::serialization::serialize<P6>::write(args, p6);
    f->call(args, ret);
    R r;
    qi::serialization::serialize<R>::read(ret, r);
    return r;
  }

  template <typename P0, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6>
  void callVoidFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    qi::serialization::serialize<P4>::write(args, p4);
    qi::serialization::serialize<P5>::write(args, p5);
    qi::serialization::serialize<P6>::write(args, p6);
    f->call(args, ret);
  }


  template <typename R, typename P0, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7>
  R callFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6, const P7 &p7) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    qi::serialization::serialize<P4>::write(args, p4);
    qi::serialization::serialize<P5>::write(args, p5);
    qi::serialization::serialize<P6>::write(args, p6);
    qi::serialization::serialize<P7>::write(args, p7);
    f->call(args, ret);
    R r;
    qi::serialization::serialize<R>::read(ret, r);
    return r;
  }

  template <typename P0, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7>
  void callVoidFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6, const P7 &p7) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    qi::serialization::serialize<P4>::write(args, p4);
    qi::serialization::serialize<P5>::write(args, p5);
    qi::serialization::serialize<P6>::write(args, p6);
    qi::serialization::serialize<P7>::write(args, p7);
    f->call(args, ret);
  }


  template <typename R, typename P0, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7, typename P8>
  R callFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6, const P7 &p7, const P8 &p8) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    qi::serialization::serialize<P4>::write(args, p4);
    qi::serialization::serialize<P5>::write(args, p5);
    qi::serialization::serialize<P6>::write(args, p6);
    qi::serialization::serialize<P7>::write(args, p7);
    qi::serialization::serialize<P8>::write(args, p8);
    f->call(args, ret);
    R r;
    qi::serialization::serialize<R>::read(ret, r);
    return r;
  }

  template <typename P0, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7, typename P8>
  void callVoidFunctor(Functor *f, const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6, const P7 &p7, const P8 &p8) {
    qi::serialization::Message args;
    qi::serialization::Message ret;

    qi::serialization::serialize<P0>::write(args, p0);
    qi::serialization::serialize<P1>::write(args, p1);
    qi::serialization::serialize<P2>::write(args, p2);
    qi::serialization::serialize<P3>::write(args, p3);
    qi::serialization::serialize<P4>::write(args, p4);
    qi::serialization::serialize<P5>::write(args, p5);
    qi::serialization::serialize<P6>::write(args, p6);
    qi::serialization::serialize<P7>::write(args, p7);
    qi::serialization::serialize<P8>::write(args, p8);
    f->call(args, ret);
  }

}
#endif  // _QI_FUNCTORS_CALLFUNCTOR_HPP_
