#pragma once
/*
*  Author(s):
*  - Cedric Gestes <gestes@aldebaran-robotics.com>
*  - Chris  Kilner <ckilner@aldebaran-robotics.com>
*
*  Copyright (C) 2010 Aldebaran Robotics
*/


#ifndef _QI_FUNCTORS_DETAIL_VOIDFUNCTOR_HXX_
#define _QI_FUNCTORS_DETAIL_VOIDFUNCTOR_HXX_

# include <qi/functors/functor.hpp>

namespace qi {
namespace detail {


  template <>
  class Functor_0<void> : public Functor
  {
  public:
    typedef void(*FunctionType) ();

    Functor_0(FunctionType pFunction)
      : fFunction(pFunction)
    {}

    void operator()() {
      (*fFunction)();
    }

    void call(qi::serialization::Message &params, qi::serialization::Message& result)const {
      QI_FUNCTOR_ASSUME_NBR_PARAMS(params, 0);

      (*fFunction)();
    };

  private:
    FunctionType  fFunction;
  };


  template <typename P0>
  class Functor_1<P0, void> : public Functor
  {
  public:
    typedef void(*FunctionType) (const P0 &p0);

    Functor_1(FunctionType pFunction)
      : fFunction(pFunction)
    {}

    void operator()(const P0 &p0) {
      (*fFunction)(p0);
    }

    void call(qi::serialization::Message &params, qi::serialization::Message& result)const {
      QI_FUNCTOR_ASSUME_NBR_PARAMS(params, 1);
      P0 p0;

      qi::serialization::serialize<P0>::read(params, p0);
      (*fFunction)(p0);
    };

  private:
    FunctionType  fFunction;
  };


  template <typename P0, typename P1>
  class Functor_2<P0, P1, void> : public Functor
  {
  public:
    typedef void(*FunctionType) (const P0 &p0, const P1 &p1);

    Functor_2(FunctionType pFunction)
      : fFunction(pFunction)
    {}

    void operator()(const P0 &p0, const P1 &p1) {
      (*fFunction)(p0, p1);
    }

    void call(qi::serialization::Message &params, qi::serialization::Message& result)const {
      QI_FUNCTOR_ASSUME_NBR_PARAMS(params, 2);
      P0 p0;
      P1 p1;

      qi::serialization::serialize<P0>::read(params, p0);
      qi::serialization::serialize<P1>::read(params, p1);
      (*fFunction)(p0, p1);
    };

  private:
    FunctionType  fFunction;
  };


  template <typename P0, typename P1, typename P2>
  class Functor_3<P0, P1, P2, void> : public Functor
  {
  public:
    typedef void(*FunctionType) (const P0 &p0, const P1 &p1, const P2 &p2);

    Functor_3(FunctionType pFunction)
      : fFunction(pFunction)
    {}

    void operator()(const P0 &p0, const P1 &p1, const P2 &p2) {
      (*fFunction)(p0, p1, p2);
    }

    void call(qi::serialization::Message &params, qi::serialization::Message& result)const {
      QI_FUNCTOR_ASSUME_NBR_PARAMS(params, 3);
      P0 p0;
      P1 p1;
      P2 p2;

      qi::serialization::serialize<P0>::read(params, p0);
      qi::serialization::serialize<P1>::read(params, p1);
      qi::serialization::serialize<P2>::read(params, p2);
      (*fFunction)(p0, p1, p2);
    };

  private:
    FunctionType  fFunction;
  };


  template <typename P0, typename P1, typename P2, typename P3>
  class Functor_4<P0, P1, P2, P3, void> : public Functor
  {
  public:
    typedef void(*FunctionType) (const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3);

    Functor_4(FunctionType pFunction)
      : fFunction(pFunction)
    {}

    void operator()(const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3) {
      (*fFunction)(p0, p1, p2, p3);
    }

    void call(qi::serialization::Message &params, qi::serialization::Message& result)const {
      QI_FUNCTOR_ASSUME_NBR_PARAMS(params, 4);
      P0 p0;
      P1 p1;
      P2 p2;
      P3 p3;

      qi::serialization::serialize<P0>::read(params, p0);
      qi::serialization::serialize<P1>::read(params, p1);
      qi::serialization::serialize<P2>::read(params, p2);
      qi::serialization::serialize<P3>::read(params, p3);
      (*fFunction)(p0, p1, p2, p3);
    };

  private:
    FunctionType  fFunction;
  };


  template <typename P0, typename P1, typename P2, typename P3, typename P4>
  class Functor_5<P0, P1, P2, P3, P4, void> : public Functor
  {
  public:
    typedef void(*FunctionType) (const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4);

    Functor_5(FunctionType pFunction)
      : fFunction(pFunction)
    {}

    void operator()(const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4) {
      (*fFunction)(p0, p1, p2, p3, p4);
    }

    void call(qi::serialization::Message &params, qi::serialization::Message& result)const {
      QI_FUNCTOR_ASSUME_NBR_PARAMS(params, 5);
      P0 p0;
      P1 p1;
      P2 p2;
      P3 p3;
      P4 p4;

      qi::serialization::serialize<P0>::read(params, p0);
      qi::serialization::serialize<P1>::read(params, p1);
      qi::serialization::serialize<P2>::read(params, p2);
      qi::serialization::serialize<P3>::read(params, p3);
      qi::serialization::serialize<P4>::read(params, p4);
      (*fFunction)(p0, p1, p2, p3, p4);
    };

  private:
    FunctionType  fFunction;
  };


  template <typename P0, typename P1, typename P2, typename P3, typename P4, typename P5>
  class Functor_6<P0, P1, P2, P3, P4, P5, void> : public Functor
  {
  public:
    typedef void(*FunctionType) (const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5);

    Functor_6(FunctionType pFunction)
      : fFunction(pFunction)
    {}

    void operator()(const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5) {
      (*fFunction)(p0, p1, p2, p3, p4, p5);
    }

    void call(qi::serialization::Message &params, qi::serialization::Message& result)const {
      QI_FUNCTOR_ASSUME_NBR_PARAMS(params, 6);
      P0 p0;
      P1 p1;
      P2 p2;
      P3 p3;
      P4 p4;
      P5 p5;

      qi::serialization::serialize<P0>::read(params, p0);
      qi::serialization::serialize<P1>::read(params, p1);
      qi::serialization::serialize<P2>::read(params, p2);
      qi::serialization::serialize<P3>::read(params, p3);
      qi::serialization::serialize<P4>::read(params, p4);
      qi::serialization::serialize<P5>::read(params, p5);
      (*fFunction)(p0, p1, p2, p3, p4, p5);
    };

  private:
    FunctionType  fFunction;
  };


  template <typename P0, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6>
  class Functor_7<P0, P1, P2, P3, P4, P5, P6, void> : public Functor
  {
  public:
    typedef void(*FunctionType) (const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6);

    Functor_7(FunctionType pFunction)
      : fFunction(pFunction)
    {}

    void operator()(const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6) {
      (*fFunction)(p0, p1, p2, p3, p4, p5, p6);
    }

    void call(qi::serialization::Message &params, qi::serialization::Message& result)const {
      QI_FUNCTOR_ASSUME_NBR_PARAMS(params, 7);
      P0 p0;
      P1 p1;
      P2 p2;
      P3 p3;
      P4 p4;
      P5 p5;
      P6 p6;

      qi::serialization::serialize<P0>::read(params, p0);
      qi::serialization::serialize<P1>::read(params, p1);
      qi::serialization::serialize<P2>::read(params, p2);
      qi::serialization::serialize<P3>::read(params, p3);
      qi::serialization::serialize<P4>::read(params, p4);
      qi::serialization::serialize<P5>::read(params, p5);
      qi::serialization::serialize<P6>::read(params, p6);
      (*fFunction)(p0, p1, p2, p3, p4, p5, p6);
    };

  private:
    FunctionType  fFunction;
  };


  template <typename P0, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7>
  class Functor_8<P0, P1, P2, P3, P4, P5, P6, P7, void> : public Functor
  {
  public:
    typedef void(*FunctionType) (const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6, const P7 &p7);

    Functor_8(FunctionType pFunction)
      : fFunction(pFunction)
    {}

    void operator()(const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6, const P7 &p7) {
      (*fFunction)(p0, p1, p2, p3, p4, p5, p6, p7);
    }

    void call(qi::serialization::Message &params, qi::serialization::Message& result)const {
      QI_FUNCTOR_ASSUME_NBR_PARAMS(params, 8);
      P0 p0;
      P1 p1;
      P2 p2;
      P3 p3;
      P4 p4;
      P5 p5;
      P6 p6;
      P7 p7;

      qi::serialization::serialize<P0>::read(params, p0);
      qi::serialization::serialize<P1>::read(params, p1);
      qi::serialization::serialize<P2>::read(params, p2);
      qi::serialization::serialize<P3>::read(params, p3);
      qi::serialization::serialize<P4>::read(params, p4);
      qi::serialization::serialize<P5>::read(params, p5);
      qi::serialization::serialize<P6>::read(params, p6);
      qi::serialization::serialize<P7>::read(params, p7);
      (*fFunction)(p0, p1, p2, p3, p4, p5, p6, p7);
    };

  private:
    FunctionType  fFunction;
  };


  template <typename P0, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7, typename P8>
  class Functor_9<P0, P1, P2, P3, P4, P5, P6, P7, P8, void> : public Functor
  {
  public:
    typedef void(*FunctionType) (const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6, const P7 &p7, const P8 &p8);

    Functor_9(FunctionType pFunction)
      : fFunction(pFunction)
    {}

    void operator()(const P0 &p0, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4, const P5 &p5, const P6 &p6, const P7 &p7, const P8 &p8) {
      (*fFunction)(p0, p1, p2, p3, p4, p5, p6, p7, p8);
    }

    void call(qi::serialization::Message &params, qi::serialization::Message& result)const {
      QI_FUNCTOR_ASSUME_NBR_PARAMS(params, 9);
      P0 p0;
      P1 p1;
      P2 p2;
      P3 p3;
      P4 p4;
      P5 p5;
      P6 p6;
      P7 p7;
      P8 p8;

      qi::serialization::serialize<P0>::read(params, p0);
      qi::serialization::serialize<P1>::read(params, p1);
      qi::serialization::serialize<P2>::read(params, p2);
      qi::serialization::serialize<P3>::read(params, p3);
      qi::serialization::serialize<P4>::read(params, p4);
      qi::serialization::serialize<P5>::read(params, p5);
      qi::serialization::serialize<P6>::read(params, p6);
      qi::serialization::serialize<P7>::read(params, p7);
      qi::serialization::serialize<P8>::read(params, p8);
      (*fFunction)(p0, p1, p2, p3, p4, p5, p6, p7, p8);
    };

  private:
    FunctionType  fFunction;
  };

}
}
#endif  // _QI_FUNCTORS_DETAIL_VOIDFUNCTOR_HXX_
